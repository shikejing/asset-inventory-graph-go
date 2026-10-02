package normalize

import (
	"testing"

	"github.com/shikejing/asset-inventory-graph-go/model"
)

func TestNormalizeIDsAndCase(t *testing.T) {
	n := NewNormalizer()
	obs, err := n.Normalize(model.RawRecord{
		Source:    "nmap",
		Hostnames: []string{"Web-01.Example.COM.", "web-01.example.com"},
		IPNets:    []string{"10.0.0.5", "10.0.0.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Hostnames) != 1 || obs.Hostnames[0] != "web-01.example.com" {
		t.Fatalf("hostname normalize: %v", obs.Hostnames)
	}
	if len(obs.IDs) != 2 { // 仅具体 IP 与主机名作为等价标识
		t.Fatalf("ids: %v", obs.IDs)
	}
	for _, id := range obs.IDs {
		if id == "net:10.0.0.0/24" {
			t.Fatalf("CIDR must not be an identity: %v", obs.IDs)
		}
	}
	if len(obs.IPNets) != 2 {
		t.Fatalf("ipnets: %v", obs.IPNets)
	}
}

func TestDedupKeyStable(t *testing.T) {
	a := model.RawRecord{Source: "s", Timestamp: 1, Hostnames: []string{"a", "b"}, IPNets: []string{"1.1.1.1"}}
	b := model.RawRecord{Source: "s", Timestamp: 1, IPNets: []string{"1.1.1.1"}, Hostnames: []string{"b", "a"}}
	if RecordDedupKey(a) != RecordDedupKey(b) {
		t.Fatal("field order must not change dedup key")
	}
	c := a
	c.Timestamp = 2
	if RecordDedupKey(a) == RecordDedupKey(c) {
		t.Fatal("different timestamp must differ")
	}
}

func TestUnionFindStableRoot(t *testing.T) {
	// 无论按什么顺序 union，同一组件根都必须是字典序最小成员。
	order1 := func() []string {
		u := NewUnionFind()
		u.UnionAll([]string{"ip:10.0.0.5", "host:a"})
		u.UnionAll([]string{"host:a", "host:b"})
		return u.Members(u.Find("host:b"))
	}
	order2 := func() []string {
		u := NewUnionFind()
		u.UnionAll([]string{"host:b", "host:a"})
		u.UnionAll([]string{"ip:10.0.0.5", "host:b"})
		return u.Members(u.Find("host:a"))
	}
	m1, m2 := order1(), order2()
	if len(m1) != 3 || m1[0] != "host:a" {
		t.Fatalf("m1=%v", m1)
	}
	for i := range m1 {
		if m1[i] != m2[i] {
			t.Fatalf("union order must not affect components: %v vs %v", m1, m2)
		}
	}
}

func TestServiceAndCredKeys(t *testing.T) {
	if got := ServiceKey(22, ""); got != "tcp/22" {
		t.Fatalf("service key: %s", got)
	}
	c1 := model.RawCredential{Username: "root", AuthType: "password", Detail: "x"}
	c2 := c1
	if CredID(22, c1) != CredID(22, c2) {
		t.Fatal("cred id must be deterministic")
	}
	c3 := c1
	c3.Detail = "y"
	if CredID(22, c1) == CredID(22, c3) {
		t.Fatal("different cred content must differ")
	}
}
