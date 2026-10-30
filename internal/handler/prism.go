package handler

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/proof"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
)

const (
	prismImageW  = 480
	prismImageH  = 320
	prismEdge    = 80  // min distance from canvas edge to gap centre
	prismGapMin  = 120 // min centre-to-centre distance between gaps
	prismTabR    = 18  // jigsaw tab circle radius (canvas rendering only)
	prismPieceW  = 100
	prismPieceH  = 100
	prismTTL     = 600 // token validity in seconds (10 min)
	prismTolPx   = 35  // acceptance radius in pixels
	prismNumGaps = 3

	// prismMaxAttemptsPerRestart bounds how many random points generateGaps
	// will try to place within a single placement attempt before giving up
	// and restarting the whole placement from scratch. A bad early point can
	// make the remaining box unsatisfiable, so retrying only the failing
	// point can never make progress — the fix is to restart, not retry.
	prismMaxAttemptsPerRestart = 200
	// prismMaxRestarts bounds how many times generateGaps will restart the
	// whole placement before giving up and returning prismFallbackGaps.
	prismMaxRestarts = 50
)

// prismFallbackGaps is a fixed, precomputed triple that satisfies both the
// prismEdge and prismGapMin constraints. It is returned by generateGaps only
// if random placement exhausts prismMaxRestarts, so the puzzle always
// renders instead of hanging or 500ing.
var prismFallbackGaps = [prismNumGaps]prismGap{
	{X: 80, Y: 80},
	{X: 320, Y: 80},
	{X: 200, Y: 239},
}

type prismGap struct{ X, Y int }

type parsedPrismToken struct {
	ImageID    int
	Gaps       [prismNumGaps]prismGap
	CorrectIdx int
	IP         string
	Expiry     int64
}

// randInt returns a cryptographically random integer in [0, n).
func randInt(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}

// generateGaps produces prismNumGaps non-overlapping gap centres that lie
// at least prismEdge pixels from every canvas edge and at least prismGapMin
// pixels from each other.
func generateGaps() ([prismNumGaps]prismGap, error) {
	xRange := prismImageW - 2*prismEdge
	yRange := prismImageH - 2*prismEdge

	for restart := 0; restart < prismMaxRestarts; restart++ {
		var gaps [prismNumGaps]prismGap
		placed := 0
		for attempt := 0; attempt < prismMaxAttemptsPerRestart && placed < prismNumGaps; attempt++ {
			rx, err := randInt(xRange)
			if err != nil {
				return gaps, err
			}
			ry, err := randInt(yRange)
			if err != nil {
				return gaps, err
			}
			cx, cy := rx+prismEdge, ry+prismEdge

			ok := true
			for j := 0; j < placed; j++ {
				dx := float64(cx - gaps[j].X)
				dy := float64(cy - gaps[j].Y)
				if math.Sqrt(dx*dx+dy*dy) < prismGapMin {
					ok = false
					break
				}
			}
			if ok {
				gaps[placed] = prismGap{cx, cy}
				placed++
			}
		}
		if placed == prismNumGaps {
			return gaps, nil
		}
		// This restart could not complete a full set within the attempt
		// budget — the accepted points so far may have made the remaining
		// box unsatisfiable. Restarting the whole placement (not just the
		// failing point) is the only way to make progress in that case.
	}
	// Exhausted all restarts (should be astronomically unlikely in a
	// 320x160 box with only 3 points). Return a known-good fallback rather
	// than looping forever or failing the request.
	return prismFallbackGaps, nil
}

// buildPrismToken HMAC-signs the challenge parameters and returns an opaque token.
// Format: base64url(payload) "." base64url(hmac-sha256)
// Payload: "{imageID}|{g0x}|{g0y}|{g1x}|{g1y}|{g2x}|{g2y}|{correctIdx}|{ip}|{expiry_unix}"
func buildPrismToken(imageID int, gaps [prismNumGaps]prismGap, correctIdx int, ip, secret string) (string, error) {
	expiry := time.Now().Unix() + prismTTL
	payload := fmt.Sprintf("%d|%d|%d|%d|%d|%d|%d|%d|%s|%d",
		imageID,
		gaps[0].X, gaps[0].Y,
		gaps[1].X, gaps[1].Y,
		gaps[2].X, gaps[2].Y,
		correctIdx,
		ip,
		expiry,
	)
	mac := prismHMAC(payload, secret)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac), nil
}

func prismHMAC(payload, secret string) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	return h.Sum(nil)
}

// parsePrismToken decodes and verifies a token produced by buildPrismToken.
func parsePrismToken(token, secret string) (*parsedPrismToken, error) {
	dot := strings.LastIndexByte(token, '.')
	if dot < 0 {
		return nil, fmt.Errorf("malformed token: no separator")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(token[:dot])
	if err != nil {
		return nil, fmt.Errorf("bad payload encoding: %w", err)
	}
	macBytes, err := base64.RawURLEncoding.DecodeString(token[dot+1:])
	if err != nil {
		return nil, fmt.Errorf("bad mac encoding: %w", err)
	}

	payload := string(payloadBytes)
	if !hmac.Equal(macBytes, prismHMAC(payload, secret)) {
		return nil, fmt.Errorf("invalid hmac")
	}

	fields := strings.Split(payload, "|")
	if len(fields) != 10 {
		return nil, fmt.Errorf("wrong field count: %d", len(fields))
	}

	toInt := func(s string) (int, error) { return strconv.Atoi(s) }
	toInt64 := func(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }

	imageID, err := toInt(fields[0])
	if err != nil {
		return nil, fmt.Errorf("imageID: %w", err)
	}
	g0x, err := toInt(fields[1])
	if err != nil {
		return nil, fmt.Errorf("g0x: %w", err)
	}
	g0y, err := toInt(fields[2])
	if err != nil {
		return nil, fmt.Errorf("g0y: %w", err)
	}
	g1x, err := toInt(fields[3])
	if err != nil {
		return nil, fmt.Errorf("g1x: %w", err)
	}
	g1y, err := toInt(fields[4])
	if err != nil {
		return nil, fmt.Errorf("g1y: %w", err)
	}
	g2x, err := toInt(fields[5])
	if err != nil {
		return nil, fmt.Errorf("g2x: %w", err)
	}
	g2y, err := toInt(fields[6])
	if err != nil {
		return nil, fmt.Errorf("g2y: %w", err)
	}
	correctIdx, err := toInt(fields[7])
	if err != nil {
		return nil, fmt.Errorf("correctIdx: %w", err)
	}
	ip := fields[8]
	expiry, err := toInt64(fields[9])
	if err != nil {
		return nil, fmt.Errorf("expiry: %w", err)
	}

	return &parsedPrismToken{
		ImageID:    imageID,
		Gaps:       [prismNumGaps]prismGap{{g0x, g0y}, {g1x, g1y}, {g2x, g2y}},
		CorrectIdx: correctIdx,
		IP:         ip,
		Expiry:     expiry,
	}, nil
}

// servePrism generates a fresh puzzle and renders the challenge page.
func (h *Handler) servePrism(w http.ResponseWriter, r *http.Request) {
	returnURL := safeReturnURL(r.URL.Query().Get("return"))

	imageID, err := randInt(1000)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	imageID++ // range 1–1000

	gaps, err := generateGaps()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	correctIdx, err := randInt(prismNumGaps)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	ipKey := h.ipKey(r)
	token, err := buildPrismToken(imageID, gaps, correctIdx, ipKey, h.cfg.HMACSecret)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// The page solves Lumen while the visitor works the puzzle, so solving
	// the puzzle alone never gets a bot through for free.
	lp := h.lumenPrismParams(r, ipKey)
	sp, err := h.proofs.Issue(ipKey, proof.KindPrism, nil, prismTTL*time.Second, proof.Options{Lumen: &lp})
	if err != nil {
		log.Printf("proof issue error: %v", err)
		w.Header().Set("Retry-After", "10")
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}

	type gapJS struct {
		X int `json:"x"`
		Y int `json:"y"`
	}
	gapsRaw, _ := json.Marshal([]gapJS{
		{gaps[0].X, gaps[0].Y},
		{gaps[1].X, gaps[1].Y},
		{gaps[2].X, gaps[2].Y},
	})

	loc := negotiateLocale(w, r)
	data := map[string]interface{}{
		"Lang":      loc.Lang,
		"T":         loc.T,
		"ReturnURL": returnURL,
		"Token":     token,
		"VerifyURL": h.prismPath + "/verify",
		"ImageID":   imageID,
		"PieceX":    gaps[correctIdx].X,
		"PieceY":    gaps[correctIdx].Y,
		"PieceW":    prismPieceW,
		"PieceH":    prismPieceH,
		"TabR":      prismTabR,
		"GapsJSON":  template.JS(gapsRaw),
		"Error":     r.URL.Query().Get("error") == "1",
		"NoJSPath":  h.noJSPath,
		"Footer":    h.footer(r, true),
		"LumenID":   sp.ID,
		"Lumen":     sp.Client().Lumen,
		"ProofJS":   h.proofJS,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := h.prismTmpl.Execute(w, data); err != nil {
		log.Printf("prism template error: %v", err)
	}
}

// servePrismVerify handles the POST from the puzzle challenge page.
func (h *Handler) servePrismVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	xStr := r.FormValue("x")
	yStr := r.FormValue("y")
	returnURL := safeReturnURL(r.FormValue("return"))
	signalsRaw := r.FormValue("signals")

	ipKey := h.ipKey(r)
	prismASN, _, _ := h.clientASN(r)

	var signals map[string]interface{}
	if signalsRaw != "" {
		json.Unmarshal([]byte(signalsRaw), &signals) //nolint:errcheck
	}

	if boolVal(signals, "webdriver") {
		log.Printf("BLOCK webdriver ip=%s ua=%q", ipKey, r.UserAgent())
		h.emit(h.newEvent(r, ipKey, 0, "", "BLOCK", "webdriver", 0))
		h.offenders.Fail(ipKey)
		h.reputation.Record(ipKey, prismASN, reputation.Webdriver)
		h.serveBlocked(w, r)
		return
	}

	if token == "" {
		log.Printf("PRISM FAIL no_token ip=%s", ipKey)
		h.emit(h.newEvent(r, ipKey, 0, "", "FAIL", "prism_no_token", 0))
		h.offenders.Fail(ipKey)
		h.reputation.Record(ipKey, prismASN, reputation.VerifyFailure)
		http.Error(w, "missing token", http.StatusForbidden)
		return
	}

	pt, err := parsePrismToken(token, h.cfg.HMACSecret)
	if err != nil {
		log.Printf("PRISM FAIL bad_token ip=%s err=%v", ipKey, err)
		h.emit(h.newEvent(r, ipKey, 0, "", "FAIL", "prism_bad_token", 0))
		h.offenders.Fail(ipKey)
		h.reputation.Record(ipKey, prismASN, reputation.VerifyFailure)
		http.Error(w, "invalid token", http.StatusForbidden)
		return
	}

	if time.Now().Unix() > pt.Expiry {
		log.Printf("PRISM FAIL expired ip=%s", ipKey)
		h.emit(h.newEvent(r, ipKey, 0, "", "FAIL", "prism_expired", 0))
		h.offenders.Fail(ipKey)
		h.reputation.Record(ipKey, prismASN, reputation.VerifyFailure)
		target := withVerdict(r, h.prismPath+"?return="+url.QueryEscape(returnURL)+"&error=1")
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	if pt.IP != ipKey {
		log.Printf("PRISM FAIL ip_mismatch token_ip=%s req_ip=%s", pt.IP, ipKey)
		h.emit(h.newEvent(r, ipKey, 0, "", "FAIL", "prism_ip_mismatch", 0))
		h.offenders.Fail(ipKey)
		h.reputation.Record(ipKey, prismASN, reputation.VerifyFailure)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// A structurally valid, unexpired, IP-matched Prism token proves this
	// client ran the puzzle page's JavaScript and answered — recorded before
	// scoring, same rule as the Lumen check on the challenge page.
	h.offenders.Answered(ipKey)

	lres, r := h.checkPrismLumen(r, ipKey)
	if lres.busy {
		lumenBusy(w)
		return
	}
	lumenShadow := lres.shadow
	if lres.failure != "" {
		if h.cfg.Lumen.Enforce {
			log.Printf("PRISM FAIL %s ip=%s ua=%q", lres.failure, ipKey, r.UserAgent())
			h.emit(h.newEvent(r, ipKey, 0, "", "FAIL", lres.failure, 0))
			h.offenders.Fail(ipKey)
			h.reputation.Record(ipKey, prismASN, reputation.VerifyFailure)
			http.Error(w, "challenge failed", http.StatusForbidden)
			return
		}
		// Prism never asked for Lumen before it, so shadow mode doesn't
		// fail an answer over any part of it.
		log.Printf("LUMEN shadow prism %s ip=%s ua=%q", lres.failure, ipKey, r.UserAgent())
		lumenShadow = lres.failure
	}

	dropX, errX := strconv.ParseFloat(xStr, 64)
	dropY, errY := strconv.ParseFloat(yStr, 64)
	if errX != nil || errY != nil {
		dropX, dropY = -1, -1
	}

	correct := pt.Gaps[pt.CorrectIdx]
	dx := dropX - float64(correct.X)
	dy := dropY - float64(correct.Y)
	dist := math.Sqrt(dx*dx + dy*dy)

	score, reasons := reflexPrismScore(signals)
	if lumenShadow != "" {
		reasons = append(reasons, lumenShadow)
	}
	logCtx := fmt.Sprintf("ip=%s score=%d reasons=%v ua=%q", ipKey, score, reasons, r.UserAgent())

	if score >= scoreBlock {
		log.Printf("BLOCK prism_signals %s", logCtx)
		ev := h.newEvent(r, ipKey, 0, "", "BLOCK", "prism_signals", score)
		ev.Reasons = reasons
		h.emit(ev)
		h.offenders.Fail(ipKey)
		h.reputation.Record(ipKey, prismASN, reputation.VerifyFailure)
		h.serveBlocked(w, r)
		return
	}

	if dist > prismTolPx {
		log.Printf("PRISM FAIL wrong_position dist=%.1f %s", dist, logCtx)
		ev := h.newEvent(r, ipKey, 0, "", "FAIL", "prism_wrong_position", score)
		ev.Reasons = reasons
		h.emit(ev)
		h.offenders.Fail(ipKey)
		h.reputation.Record(ipKey, prismASN, reputation.VerifyFailure)
		target := withVerdict(r, h.prismPath+"?return="+url.QueryEscape(returnURL)+"&error=1")
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	log.Printf("PASS prism %s", logCtx)
	ev := h.newEvent(r, ipKey, 0, "", "PASS", "prism", score)
	ev.Reasons = reasons
	h.emit(ev)
	h.offenders.Success(ipKey)
	h.reputation.Record(ipKey, prismASN, reputation.CleanPass)
	h.escalations.Clear(ipKey)
	h.cookies.Issue(w, ipKey, r)
	h.offenders.IncrAnsweredNoClearance(ipKey)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, returnURL, http.StatusFound)
}

// checkPrismLumen checks the Prism page's Lumen answer: the "lumen_id"
// form field names its challenge and "lumen" carries the answer as JSON.
// The challenge is spent whatever happens next.
func (h *Handler) checkPrismLumen(r *http.Request, ipKey string) (lumenResult, *http.Request) {
	sp, ok := h.proofs.Consume(r.FormValue("lumen_id"), ipKey, proof.KindPrism)
	if !ok {
		return lumenResult{failure: "lumen_missing"}, r
	}
	var answer interface{}
	json.Unmarshal([]byte(r.FormValue("lumen")), &answer) //nolint:errcheck
	return h.checkLumen(r, sp, map[string]interface{}{proof.FieldLumen: answer}, time.Since(sp.Issued))
}
