package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/shikejing/asset-inventory-graph-go/model"
)

// Normalizer 负责原始记录归一化与稳定标识计算。
// 归一化是纯函数：同样的输入永远得到同样的输出，保证去重不依赖到达顺序。
type Normalizer struct{}

// NewNormalizer 创建归一化器。
func NewNormalizer() *Normalizer { return &Normalizer{} }

// Observation 是一条原始记录归一化后的结果。
type Observation struct {
	Source    string
	Timestamp int64
	IDs       []string // 该观察涉及的稳定标识（ip: / host:）
	IPNets    []string
	Hostnames []string
	OS        string
	Domain    string
	Services  []model.RawService
	Vulns     []model.RawVuln
	DedupKey  string // 记录内容的幂等键
}

// HostID 返回主机名标识。
func HostID(name string) string {
	return "host:" + strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// NetID 返回网段/IP 标识。
func NetID(s string) string {
	s = strings.TrimSpace(s)
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		return "net:" + ipnet.String()
	}
	if ip := net.ParseIP(s); ip != nil {
		return "ip:" + ip.String()
	}
	// 无法解析时按字面量归一化，不丢弃来源数据。
	return "raw:" + strings.ToLower(s)
}

// ServiceKey 返回服务的稳定键。
func ServiceKey(port int, proto string) string {
	proto = strings.ToLower(strings.TrimSpace(proto))
	if proto == "" {
		proto = "tcp"
	}
	return proto + "/" + itoa(port)
}

// VulnID 返回漏洞节点标识。
func VulnID(v model.RawVuln) string {
	id := strings.TrimSpace(v.ID)
	if id == "" {
		id = "anon:" + hash10(v.Title+"|"+v.Description)
	}
	return "vuln:" + id
}

// CredID 返回弱口令节点标识（内容寻址，天然幂等去重）。
func CredID(port int, c model.RawCredential) string {
	p := c.ServicePort
	if p == 0 {
		p = port
	}
	return "cred:" + itoa(p) + "/" + hash10(c.Username+"|"+c.AuthType+"|"+c.Detail)
}

// Normalize 归一化单条原始记录。
func (n *Normalizer) Normalize(r model.RawRecord) (*Observation, error) {
	source := strings.TrimSpace(r.Source)
	// 给嵌套结构注入来源与时间戳，保证服务/漏洞/弱口令的冲突裁决可追溯。
	for i := range r.Services {
		r.Services[i].Source = source
		r.Services[i].Timestamp = r.Timestamp
		for j := range r.Services[i].Vulns {
			r.Services[i].Vulns[j].Source = source
			r.Services[i].Vulns[j].Timestamp = r.Timestamp
		}
		for j := range r.Services[i].Creds {
			r.Services[i].Creds[j].Source = source
			r.Services[i].Creds[j].Timestamp = r.Timestamp
		}
	}
	for i := range r.Vulns {
		r.Vulns[i].Source = source
		r.Vulns[i].Timestamp = r.Timestamp
	}
	obs := &Observation{
		Source:    source,
		Timestamp: r.Timestamp,
		OS:        strings.TrimSpace(r.OS),
		Domain:    strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Domain), ".")),
		Services:  r.Services,
		Vulns:     r.Vulns,
	}
	idSet := map[string]bool{}
	for _, nwt := range r.IPNets {
		id := NetID(nwt)
		// 只把具体 IP 作为资产等价标识；网段保留为属性，避免把整段合成一个资产。
		if strings.HasPrefix(id, "ip:") {
			idSet[id] = true
			obs.IPNets = append(obs.IPNets, strings.TrimPrefix(id, "ip:"))
		} else {
			obs.IPNets = append(obs.IPNets, strings.TrimPrefix(id, "net:"))
		}
	}
	for _, h := range r.Hostnames {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		id := HostID(h)
		idSet[id] = true
		obs.Hostnames = append(obs.Hostnames, strings.TrimPrefix(id, "host:"))
	}
	for id := range idSet {
		obs.IDs = append(obs.IDs, id)
	}
	obs.IPNets = dedupSorted(obs.IPNets)
	obs.Hostnames = dedupSorted(obs.Hostnames)
	sort.Strings(obs.IDs)
	obs.DedupKey = RecordDedupKey(r)
	return obs, nil
}

// RecordDedupKey 计算记录内容的幂等键：同一条扫描结果重复/乱序到达只生效一次。
func RecordDedupKey(r model.RawRecord) string {
	b, err := json.Marshal(canonicalRecord(r))
	if err != nil {
		b = []byte(r.Source)
	}
	sum := sha256.Sum256(b)
	return "rec:" + hex.EncodeToString(sum[:16])
}

// canonicalRecord 返回字段排序确定的可序列化结构。
func canonicalRecord(r model.RawRecord) any {
	type svc struct {
		Port     int      `json:"port"`
		Protocol string   `json:"protocol"`
		Name     string   `json:"name"`
		Version  string   `json:"version"`
		Banner   string   `json:"banner"`
		Product  string   `json:"product"`
		Vulns    []string `json:"vulns"`
		Creds    []string `json:"creds"`
	}
	ss := make([]svc, 0, len(r.Services))
	for _, s := range r.Services {
		vs := make([]string, 0, len(s.Vulns))
		for _, v := range s.Vulns {
			vs = append(vs, v.ID+"|"+v.Title)
		}
		cs := make([]string, 0, len(s.Creds))
		for _, c := range s.Creds {
			cs = append(cs, c.Username+"|"+c.AuthType+"|"+c.Detail)
		}
		sort.Strings(vs)
		sort.Strings(cs)
		ss = append(ss, svc{s.Port, s.Protocol, s.Name, s.Version, s.Banner, s.Product, vs, cs})
	}
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].Port != ss[j].Port {
			return ss[i].Port < ss[j].Port
		}
		return ss[i].Protocol < ss[j].Protocol
	})
	hn := append([]string{}, r.Hostnames...)
	nw := append([]string{}, r.IPNets...)
	sort.Strings(hn)
	sort.Strings(nw)
	return struct {
		Source    string   `json:"source"`
		Timestamp int64    `json:"timestamp"`
		Hostnames []string `json:"hostnames"`
		IPNets    []string `json:"ipnets"`
		OS        string   `json:"os"`
		Domain    string   `json:"domain"`
		Services  []svc    `json:"services"`
	}{strings.TrimSpace(r.Source), r.Timestamp, hn, nw, r.OS, r.Domain, ss}
}

func dedupSorted(in []string) []string {
	set := map[string]bool{}
	for _, v := range in {
		if v != "" {
			set[v] = true
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func hash10(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:5])
}

func itoa(i int) string { return strconv.Itoa(i) }
