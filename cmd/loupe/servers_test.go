package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestProxyServerDropsSlowHeaders(t *testing.T) {
	old := headerTimeout
	headerTimeout = 100 * time.Millisecond
	defer func() { headerTimeout = old }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newProxyServer("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	go srv.Serve(ln)
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// A request line and one header, never the blank line that ends them.
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n")); err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	_, err = io.Copy(io.Discard, conn)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("server kept a connection with stalled headers open")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("stalled connection closed after %v, want within 1s of the header timeout", elapsed)
	}
}

func TestProxyServerNoWriteTimeout(t *testing.T) {
	srv := newProxyServer(":0", http.NotFoundHandler())
	if srv.WriteTimeout != 0 || srv.ReadTimeout != 0 {
		t.Errorf("ReadTimeout=%v WriteTimeout=%v, want both 0 so uploads and streamed responses pass through", srv.ReadTimeout, srv.WriteTimeout)
	}
	if srv.IdleTimeout < 10*time.Minute {
		t.Errorf("IdleTimeout=%v, want at least 10m so it stays above Caddy's 2m upstream keep-alive", srv.IdleTimeout)
	}
	if srv.ReadHeaderTimeout == 0 || srv.IdleTimeout == 0 || srv.MaxHeaderBytes == 0 {
		t.Errorf("header timeout=%v idle=%v max header bytes=%d, want all set", srv.ReadHeaderTimeout, srv.IdleTimeout, srv.MaxHeaderBytes)
	}
}

// An in-flight request must finish before the after hooks run, and the hooks
// must run in order.
func TestShutdownDrainsThenRunsHooksInOrder(t *testing.T) {
	var mu sync.Mutex
	var order []string
	note := func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }

	inHandler := make(chan struct{})
	release := make(chan struct{})
	srv := newProxyServer("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(inHandler)
		<-release
		note("request finished")
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	other := newProxyServer("", http.NotFoundHandler())
	otherLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	otherServed := make(chan error, 1)
	go func() { otherServed <- other.Serve(otherLn) }()

	go http.Get("http://" + ln.Addr().String() + "/")
	<-inHandler

	finished := make(chan struct{})
	go func() {
		shutdown(5*time.Second, []*http.Server{srv, other}, func() { note("hook 1") }, func() { note("hook 2") })
		close(finished)
	}()
	select {
	case <-finished:
		t.Fatal("shutdown returned while a request was still in flight")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not finish after the request completed")
	}

	mu.Lock()
	defer mu.Unlock()
	select {
	case err := <-otherServed:
		if err != http.ErrServerClosed {
			t.Errorf("second server Serve = %v, want ErrServerClosed", err)
		}
	default:
		t.Error("second server was not shut down")
	}
	want := []string{"request finished", "hook 1", "hook 2"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
}

// Shutdown makes ListenAndServe return immediately; serve must still block
// until the shutdown sequence reports done, or the process exits mid-flush.
func TestServeWaitsForShutdownToFinish(t *testing.T) {
	srv := newProxyServer("127.0.0.1:0", http.NotFoundHandler())
	done := make(chan struct{})
	returned := make(chan error, 1)
	go func() { returned <- serve(srv, done) }()

	time.Sleep(100 * time.Millisecond) // let ListenAndServe start
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-returned:
		t.Fatalf("serve returned (%v) before the shutdown sequence finished", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(done)
	select {
	case err := <-returned:
		if err != nil {
			t.Errorf("serve = %v after a clean shutdown, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after done was closed")
	}
}

func TestServeReturnsListenError(t *testing.T) {
	// Occupy a loopback port so ListenAndServe fails with "address already in
	// use" without any DNS lookup.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := newProxyServer(ln.Addr().String(), http.NotFoundHandler())
	if err := serve(srv, make(chan struct{})); err == nil {
		t.Fatal("serve returned nil for an address already in use")
	}
}
