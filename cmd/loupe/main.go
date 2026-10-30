package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/admin"
	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/handler"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
	"github.com/AUPLA-Labs/loupe/internal/version"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)

	cfgPath := "config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	if cfgPath == "-version" || cfgPath == "--version" {
		fmt.Println("loupe", version.String())
		return
	}
	if cfgPath == "install" {
		if err := installMain(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "loupe install:", err)
			os.Exit(1)
		}
		return
	}

	if cfgPath == "-setup-admin" {
		if err := setupAdminMain(os.Args[2:]); err != nil {
			log.Fatalf("setup-admin: %v", err)
		}
		return
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	store, err := admin.OpenStore(admin.StoreOptions{
		Capacity: cfg.Admin.Capacity,
		MaxAge:   cfg.Admin.MaxAge(),
		LogPath:  cfg.Admin.LogPath,
		PruneLog: *cfg.Admin.PruneLog,
	})
	if err != nil {
		log.Fatalf("admin store: %v", err)
	}
	defer store.Close()

	repStore := reputation.New(reputation.Config{
		HalfLife:                time.Duration(cfg.Reputation.HalfLifeHours * float64(time.Hour)),
		Floors:                  reputation.Floors(cfg.Reputation.Floors),
		NonDatacenterMultiplier: cfg.Reputation.NonDatacenterMultiplier,
		SnapshotPath:            cfg.Reputation.SnapshotPath,
		SnapshotInterval:        time.Duration(cfg.Reputation.SnapshotIntervalSeconds) * time.Second,
	})

	if cfg.Admin.AuthError != "" {
		// The proxy still starts; only the dashboard waits for the fix.
		log.Printf("admin: %s; the dashboard is locked until it is fixed (loupe -setup-admin can repair it)", cfg.Admin.AuthError)
	}
	adminSrv := admin.NewServer(store, repStore, cfgPath, admin.AuthOptions{
		File:         cfg.Admin.AuthFile,
		Users:        cfg.Admin.Users,
		SessionsPath: sessionsPath(cfg.Admin.AuthFile),
		Require2FA:   cfg.Admin.Require2FA,
		LoadError:    cfg.Admin.AuthError,
		// Next to the users file, which setup creates.
		SetupTokenFile: filepath.Join(filepath.Dir(cfg.Admin.AuthFile), "setup_token"),
	})

	audit, err := admin.NewAudit(cfg.Admin.AuditPath)
	if err != nil {
		log.Printf("admin: audit log disabled: %v", err) // NewAudit returned nil, which records nothing
	}
	adminSrv.SetAudit(audit)
	hist := config.NewHistory(cfg.Admin.HistoryDir, cfg.Admin.HistoryKeep)
	adminSrv.SetHistory(hist)
	seedHistory(hist, "config", cfgPath) // before the listener, so a first save keeps the baseline

	if err := adminSrv.SetAllow(cfg.Admin.Allow); err != nil {
		log.Fatalf("admin.allow: %v", err) // config.Load already checked it
	}
	adminHTTP := adminSrv.HTTPServer(cfg.Admin.Listen)
	for _, u := range adminSrv.SetupURLs() {
		log.Printf("admin: no admin yet, create one at %s", u)
	}
	go func() {
		log.Printf("admin UI at http://%s", cfg.Admin.Listen)
		if err := adminHTTP.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("admin server stopped: %v", err)
		}
	}()

	h, err := handler.New(cfg, store, repStore)
	if err != nil {
		log.Fatalf("init handler: %v", err)
	}

	seedHistory(hist, "bots", h.Bots().PolicyFile())
	h.Bots().SetOnPolicyWritten(func(b []byte) {
		if _, err := hist.Save("bots", b); err != nil {
			log.Printf("admin: record bots version: %v", err)
		}
	})
	adminSrv.SetClientIP(h.ClientIP())
	adminSrv.SetBots(h.Bots())
	adminSrv.SetRobotsPreview(h.RobotsPreview)
	adminSrv.SetBadIPs(h.BadIPs())
	adminSrv.SetASN(h.ASN())
	go h.Bots().Run(context.Background())
	go h.BadIPs().Run(context.Background())
	seedHistory(hist, "rules", h.Rules().Path())
	adminSrv.SetRules(h.Rules(), h.TestRules)
	adminSrv.SetAPIKeys(h.APIKeys())
	go h.APIKeys().Run()
	adminSrv.SetUnderAttack(h.UnderAttack())
	go h.Rules().Run(context.Background())
	go h.ASN().Run(context.Background())

	proxyHTTP := newProxyServer(cfg.Listen, h)

	// Honour SIGTERM/SIGINT: drain both listeners, then flush state. main
	// returns only once this is done (see serve), and its deferred
	// store.Close runs last.
	done := make(chan struct{})
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		sig := <-ch
		log.Printf("received %v, shutting down", sig)
		shutdown(10*time.Second, []*http.Server{proxyHTTP, adminHTTP}, func() {
			if cfg.Reputation.SnapshotPath != "" {
				if err := repStore.Snapshot(cfg.Reputation.SnapshotPath); err != nil {
					log.Printf("reputation: final snapshot failed: %v", err)
				}
			}
		}, h.Close)
		close(done)
	}()

	log.Printf("Loupe listening on %s → %s", cfg.Listen, cfg.Backend)
	if err := serve(proxyHTTP, done); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// seedHistory records the file as it stands, so the first dashboard save has
// a version to compare against. Saving unchanged bytes again stores nothing.
func seedHistory(hist *config.History, name, path string) {
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		log.Printf("admin: seed %s history: %v", name, err)
		return
	}
	if _, err := hist.Save(name, data); err != nil {
		log.Printf("admin: seed %s history: %v", name, err)
	}
}

// sessionsPath keeps admin login sessions beside the credentials file, which
// setup-admin already creates with a 0700 directory.
func sessionsPath(authFile string) string {
	if authFile == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(authFile), "admin_sessions.json")
}
