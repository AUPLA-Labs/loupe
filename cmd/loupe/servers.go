package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"
)

// headerTimeout bounds how long a client may take to send its request
// headers; a var so tests can shorten it.
var headerTimeout = 10 * time.Second

// newProxyServer builds the public listener. It deliberately sets no
// ReadTimeout or WriteTimeout: those cap the whole request and response, which
// would cut off large uploads and streamed or slow downloads being proxied.
// The header timeout still drops slowloris clients, and the idle timeout
// reclaims keep-alive connections.
//
// The idle timeout must stay above the front proxy's upstream keep-alive
// (Caddy 2m, Traefik 90s, nginx 60s when enabled): if Loupe closes first, the
// proxy can reuse a connection that is going away and return a 502, notably on
// POST. Idle connections from one proxy cost little, so a long timeout is
// cheap.
func newProxyServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: headerTimeout,
		IdleTimeout:       10 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
}

// shutdown stops accepting connections and waits, up to timeout across all
// servers, for in-flight requests to finish, then runs the after hooks in
// order. The hooks flush state that those requests may still have written.
func shutdown(timeout time.Duration, servers []*http.Server, after ...func()) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown %s: %v", srv.Addr, err)
		}
	}
	for _, f := range after {
		f()
	}
}

// serve runs srv until it fails or is shut down. Shutdown makes
// ListenAndServe return http.ErrServerClosed at once, while the drain and
// flush are still running elsewhere, so wait for done before returning and
// letting the process exit.
func serve(srv *http.Server, done <-chan struct{}) error {
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		<-done
		return nil
	}
	return err
}
