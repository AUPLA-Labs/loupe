package handler

import (
	"bytes"
	"encoding/json"
	"html/template"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/lumen"
	"github.com/AUPLA-Labs/loupe/internal/proof"
)

// TestWriteProofSelftest writes a standalone HTML page that runs proof.js
// against many server-generated challenges in a real browser and checks
// every answer against the Go side: layout rects, computed colour, seal
// byte-compatibility, and Lumen answers at every level (whose timings make
// the page double as a device benchmark). Open it in each engine (and at a few zoom levels /
// display scalings) before deploying changes to internal/proof or proof.js.
//
//	LOUPE_SELFTEST_OUT=/tmp/proof-selftest.html go test ./internal/handler -run ProofSelftest
func TestWriteProofSelftest(t *testing.T) {
	out := os.Getenv("LOUPE_SELFTEST_OUT")
	if out == "" {
		t.Skip("set LOUPE_SELFTEST_OUT to write the browser self-test page")
	}
	js, err := staticFiles.ReadFile("proof.js")
	if err != nil {
		t.Fatal(err)
	}

	type sealCase struct {
		Spec   proof.ClientSpec       `json:"spec"`
		In     map[string]interface{} `json:"in"`
		Sealed string                 `json:"sealed"`
	}
	type layoutCase struct {
		Spec  proof.ClientSpec `json:"spec"`
		Rects [][4]float64     `json:"rects"`
		Color [3]int           `json:"color"`
	}

	store := proof.NewStore(10000)
	fields := []string{"screenW", "languages", "webdriver", "mousePath"}
	var layouts []layoutCase
	var seals []sealCase
	for i := 0; i < 500; i++ {
		sp, err := store.Issue("selftest", proof.KindPulse, fields, time.Hour, proof.Options{})
		if err != nil {
			t.Fatal(err)
		}
		lc := layoutCase{Spec: sp.Client(), Color: sp.Color.RGB()}
		for _, b := range sp.Boxes {
			r := b.Expected(sp.ContainerW)
			lc.Rects = append(lc.Rects, [4]float64{r.X, r.Y, r.W, r.H})
		}
		layouts = append(layouts, lc)

		if i < 50 {
			// Insert keys in sorted order on the JS side (the page does) so
			// JSON.stringify and Go's sorted-key json.Marshal agree byte for
			// byte once fields are renamed — the renamed order is then
			// checked by unsealing, not by comparing ciphertexts.
			in := map[string]interface{}{
				"screenW":   1920,
				"languages": "de-AT,de,ü€😀",
				"webdriver": false,
				"mousePath": []interface{}{[]interface{}{1, 2, 3}},
			}
			sealed, err := sp.Seal(in)
			if err != nil {
				t.Fatal(err)
			}
			seals = append(seals, sealCase{Spec: sp.Client(), In: in, Sealed: sealed})
		}
	}

	// Lumen at every level of the default config, pulse and challenge
	// page: Go solves each so the page can check LoupeProof.solve
	// (Worker and its main-thread fallback) and time it on this device.
	type lumenCase struct {
		Name    string                `json:"name"`
		Ch      lumen.ClientChallenge `json:"ch"`
		Numbers []int64               `json:"numbers"`
		Digest  string                `json:"digest"`
	}
	cfg, err := config.LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{cfg: cfg}
	var lumens []lumenCase
	for _, page := range []struct {
		name  string
		pulse bool
	}{{"pulse", true}, {"challenge", false}} {
		for l := lumen.Glow; l <= lumen.MaxLevel; l++ {
			p := lumen.ParamsFor(l, h.lumenBase(page.pulse))
			if p.Level != l {
				continue // clamped: same as the level before
			}
			c, err := lumen.New(p)
			if err != nil {
				t.Fatal(err)
			}
			a, ok := lumen.Solve(c.Client())
			if !ok {
				t.Fatal("no Lumen solution found")
			}
			lumens = append(lumens, lumenCase{
				Name: page.name + " " + l.String() + " (" + strconv.FormatInt(p.Work, 10) + " work, " +
					strconv.FormatInt(p.MemoryBytes()>>20, 10) + " MB)",
				Ch: c.Client(), Numbers: a.Numbers, Digest: a.Digest,
			})
		}
	}

	data, err := json.Marshal(map[string]interface{}{"layouts": layouts, "seals": seals, "lumens": lumens})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tmpl := template.Must(template.New("selftest").Parse(selftestHTML))
	if err := tmpl.Execute(&buf, map[string]interface{}{
		"ProofJS": template.JS(js),
		"Data":    template.JS(data),
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%d layout, %d seal, %d Lumen cases)", out, len(layouts), len(seals), len(lumens))
	if !strings.Contains(buf.String(), "LoupeProof") {
		t.Error("proof.js was not inlined")
	}
}

const selftestHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Loupe proof self-test</title>
<style>body{font:14px system-ui,sans-serif;margin:16px}pre{white-space:pre-wrap}.ok{color:#080}.bad{color:#b00}</style>
</head><body>
<h1>Loupe proof self-test</h1>
<p id="env"></p>
<p id="summary">running…</p>
<pre id="log"></pre>
<script>{{.ProofJS}}</script>
<script>
(function () {
  var D = {{.Data}};
  var log = document.getElementById('log');
  var bad = 0, total = 0;
  function fail(msg) { bad++; log.textContent += msg + '\n'; }

  document.getElementById('env').textContent =
    navigator.userAgent + ' — devicePixelRatio ' + window.devicePixelRatio;

  // Layout and colour: same tolerances as internal/proof.
  D.layouts.forEach(function (c, i) {
    total++;
    var got = LoupeProof.measure(c.spec);
    var ok = got.rects.length === c.rects.length;
    for (var b = 0; ok && b < c.rects.length; b++) {
      for (var k = 0; k < 4; k++) {
        if (Math.abs(got.rects[b][k] - c.rects[b][k]) > 1) ok = false;
      }
    }
    if (!ok) fail('layout #' + i + ' got ' + JSON.stringify(got.rects) + ' want ' + JSON.stringify(c.rects) + ' css ' + JSON.stringify(c.spec.x));
    var m = /^rgb\(([^)]*)\)$/.exec(got.color.trim());
    var parts = m ? m[1].split(/[ ,]+/).map(Number) : [];
    var cok = parts.length === 3 && parts.every(function (v, j) { return Math.abs(v - c.color[j]) <= 1; });
    if (!cok) fail('colour #' + i + ' got ' + got.color + ' want rgb(' + c.color.join(', ') + ') from ' + c.spec.c);
  });

  // Seal: unseal Go's ciphertext with the JS keystream (seal is a plain XOR,
  // so sealing the decoded bytes again inverts it) and compare to what Go
  // would have produced — proves both sides generate the same keystream
  // and UTF-8 bytes.
  D.seals.forEach(function (c, i) {
    total++;
    var renamed = {};
    Object.keys(c.in).forEach(function (k) { renamed[c.spec.f[k]] = c.in[k]; });
    var sorted = {};
    Object.keys(renamed).sort().forEach(function (k) { sorted[k] = renamed[k]; });
    var identity = {};
    Object.keys(sorted).forEach(function (k) { identity[k] = k; });
    var jsSealed = LoupeProof.seal({ a: c.spec.a, b: c.spec.b, f: identity }, sorted);
    if (jsSealed !== c.sealed) fail('seal #' + i + ' JS ' + jsSealed + ' != Go ' + c.sealed);
  });

  function report() {
    var s = document.getElementById('summary');
    s.className = bad ? 'bad' : 'ok';
    s.textContent = bad ? (bad + ' of ' + total + ' checks FAILED') : ('all ' + total + ' checks passed');
  }

  // Lumen, solved sequentially so timings are per challenge.
  var chain = Promise.resolve();
  D.lumens.forEach(function (c) {
    chain = chain.then(function () {
      total++;
      return LoupeProof.solve(c.ch).then(function (r) {
        var a = r.answer;
        if (a.n.join(',') !== c.numbers.join(',')) fail(c.name + ': numbers ' + a.n + ' want ' + c.numbers);
        else if (a.d !== c.digest) fail(c.name + ': space digest ' + (a.d || '(none)') + ' want ' + c.digest);
        else log.textContent += c.name + ': work ' + a.w + ' ms, space ' + a.s + ' ms' + (r.nav ? '' : ' (main thread)') + '\n';
      }, function (err) { fail(c.name + ': error ' + err); });
    });
  });
  chain.then(report);
}());
</script>
</body></html>`
