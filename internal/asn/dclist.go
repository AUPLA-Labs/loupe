package asn

// The datacenter ASN list: a published file of networks that count as
// datacenters, which Loupe downloads into the datacenter file itself (a
// conditional GET, so an unchanged list costs one 304). A failed or
// implausible download keeps the last good list, in memory and on disk.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// maxDCList bounds a list download; the published one is well under 1 MB.
const maxDCList = 16 << 20

// dcRetry is how soon a failed download is tried again.
const dcRetry = time.Hour

// runDatacenterList refreshes the list now if the file is missing or older
// than dcEvery, then every dcEvery, until ctx is done.
func (d *DB) runDatacenterList(ctx context.Context) {
	wait := time.Duration(0)
	if st, err := os.Stat(d.dcFile); err == nil {
		wait = max(0, d.dcEvery-time.Since(st.ModTime()))
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		next := d.dcEvery
		if err := d.refreshDatacenterList(ctx); err != nil {
			log.Printf("asn: datacenter list %s: %v (keeping the previous one)", d.dcURL, err)
			next = dcRetry
		}
		t.Reset(next)
	}
}

// refreshDatacenterList downloads the list once and, if it holds at least one
// ASN, writes it to the datacenter file and swaps it in.
func (d *DB) refreshDatacenterList(ctx context.Context) error {
	d.dcMu.Lock()
	defer d.dcMu.Unlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.dcURL, nil)
	if err != nil {
		return err
	}
	if d.dcAgent != "" {
		req.Header.Set("User-Agent", d.dcAgent)
	}
	if d.dcETag != "" {
		req.Header.Set("If-None-Match", d.dcETag)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		// Unchanged: mark the file fresh so a restart doesn't fetch it again.
		now := time.Now()
		return os.Chtimes(d.dcFile, now, now)
	case http.StatusOK:
	default:
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDCList+1))
	if err != nil {
		return err
	}
	if len(body) > maxDCList {
		return fmt.Errorf("larger than %d bytes", maxDCList)
	}
	list := map[uint]bool{}
	if err := parseASNs(bytes.NewReader(body), list); err != nil {
		return err
	}
	if len(list) == 0 {
		return errors.New("no ASNs in the response")
	}
	if err := writeFileAtomic(d.dcFile, body); err != nil {
		return err
	}
	d.dcList.Store(&list)
	d.dcETag = resp.Header.Get("ETag")
	log.Printf("asn: datacenter list: %d networks", len(list))
	return nil
}

// writeFileAtomic replaces path with data, so a reader never sees half a file.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".datacenter-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
