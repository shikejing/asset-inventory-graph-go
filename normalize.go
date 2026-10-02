package inventory

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
)

// NormalizeHostname canonicalizes a hostname for identity convergence:
// lower-cased, trimmed, trailing dot removed.
func NormalizeHostname(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	return h
}

// NormalizeIP canonicalizes an IP address. Returns ("", false) for garbage.
func NormalizeIP(ip string) (string, bool) {
	ip = strings.TrimSpace(ip)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	return parsed.String(), true
}

// NormalizeMAC canonicalizes a MAC address to lower-case hex without
// separators. Returns ("", false) for garbage.
func NormalizeMAC(m string) (string, bool) {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(m)) {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'a' && r <= 'f':
			b.WriteRune(r)
		}
	}
	if b.Len() != 12 {
		return "", false
	}
	return b.String(), true
}

// identityKeys returns the stable identity keys of a record. Records that
// share any identity key are considered the same asset. Keys are namespaced
// by kind to avoid collisions (e.g. "ip:1.2.3.4" vs "hn:1.2.3.4").
func (r *RawRecord) identityKeys() []string {
	seen := map[string]bool{}
	var keys []string
	add := func(k string) {
		if k != "" && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	if hn := NormalizeHostname(r.Hostname); hn != "" {
		add("hn:" + hn)
	}
	for _, ip := range r.IPs {
		if n, ok := NormalizeIP(ip); ok {
			add("ip:" + n)
		}
	}
	for _, mac := range r.MACs {
		if n, ok := NormalizeMAC(mac); ok {
			add("mac:" + n)
		}
	}
	if len(keys) == 0 {
		// No identity claim: the record stands alone, keyed by its record id.
		rid := r.ID
		if rid == "" {
			rid = ContentHash(r)
		}
		add("rec:" + rid)
	}
	sort.Strings(keys)
	return keys
}

// ContentHash produces a deterministic hash of a record's content, used as a
// fallback identity key when no record id is provided.
func ContentHash(r *RawRecord) string {
	h := sha1.New()
	write := func(s string) { h.Write([]byte(s)); h.Write([]byte{0}) }
	write(string(r.Source))
	write(r.Hostname)
	write(r.Domain)
	write(r.OS)
	for _, ip := range r.IPs {
		write(ip)
	}
	for _, m := range r.MACs {
		write(m)
	}
	for _, p := range r.Ports {
		write(fmt.Sprintf("%d", p))
	}
	for _, s := range r.Services {
		write(s.Name)
		write(fmt.Sprintf("%d", s.Port))
		write(s.Version)
	}
	for k, v := range r.Attrs {
		write(k)
		write(v)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// componentID derives a deterministic component id from a set of identity
// keys. The same set of keys always yields the same id, independent of the
// order in which records arrived.
func componentID(keys []string) string {
	h := sha1.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
	}
	return "asset:" + hex.EncodeToString(h.Sum(nil))[:16]
}

// normalizeRecord returns a copy of r with canonicalized identity fields.
func normalizeRecord(r *RawRecord) *RawRecord {
	cp := *r
	cp.Hostname = NormalizeHostname(r.Hostname)
	ips := make([]string, 0, len(r.IPs))
	for _, ip := range r.IPs {
		if n, ok := NormalizeIP(ip); ok {
			ips = append(ips, n)
		}
	}
	sort.Strings(ips)
	cp.IPs = uniqSorted(ips)
	macs := make([]string, 0, len(r.MACs))
	for _, m := range r.MACs {
		if n, ok := NormalizeMAC(m); ok {
			macs = append(macs, n)
		}
	}
	sort.Strings(macs)
	cp.MACs = uniqSorted(macs)
	if r.Domain != "" {
		cp.Domain = strings.ToLower(strings.TrimSpace(r.Domain))
	}
	if cp.ID == "" {
		cp.ID = ContentHash(r)
	}
	return &cp
}

func uniqSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := in[:1]
	for _, v := range in[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}
