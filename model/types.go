package model

// RawService 是扫描来源发现的单个服务的原始描述。
// 漏洞与弱口令线索归属于具体服务（service -> vuln / weakcred）。
type RawService struct {
	Port      int
	Protocol  string // tcp/udp
	Name      string // ssh / http ...
	Version   string
	Banner    string
	Product   string
	Vulns     []RawVuln
	Creds     []RawCredential
	Source    string // 归一化时由引擎填入
	Timestamp int64
}

// RawVuln 是来源直接关联到服务或资产的漏洞线索。
type RawVuln struct {
	ID          string // CVE 或来源自定义编号
	Title       string
	Severity    string
	Description string
	Source      string // 归一化时由引擎填入
	Timestamp   int64
}

// SourceOf 返回来源（兼容直接挂在资产级的漏洞条目）。
func (v RawVuln) SourceOf() string { return v.Source }

// RawCredential 是弱口令/凭证线索。
type RawCredential struct {
	ServicePort int // 兼容记录级条目：所属端口，0 表示跟随所在服务
	Username    string
	AuthType    string // password / key
	Detail      string
	Source      string
	Timestamp   int64
}

// RawRecord 是单个扫描来源对一个资产的一次观察。
type RawRecord struct {
	Source    string
	Timestamp int64
	Hostnames []string
	IPNets    []string // CIDR 或 ip
	OS        string
	Services  []RawService
	Vulns     []RawVuln // 资产级漏洞
	Domain    string    // 归属域
}

// Provenance 记录某个字段值来自哪次来源观察。
type Provenance struct {
	Source    string `json:"source"`
	Timestamp int64  `json:"timestamp"`
	Value     string `json:"value"`
}

// Attribute 是收敛后的单值属性及其裁决依据。
type Attribute struct {
	Key      string       `json:"key"`
	Value    string       `json:"value"`
	Winner   Provenance   `json:"winner"`
	History  []Provenance `json:"history"` // 被覆盖的全部来源依据（含 Winner），按裁决顺序
	Strategy string       `json:"strategy"`
}

// ValueProvenance 是多值属性（集合合并）中的单个值及其来源依据。
type ValueProvenance struct {
	Value   string       `json:"value"`
	Sources []Provenance `json:"sources"`
}

// Service 是收敛后的服务。
type Service struct {
	Port     int
	Protocol string
	Key      string // port/proto
	Name     string
	Version  string
	Product  string
	Banner   string
	// Attrs 保存 name/version/product/banner 的冲突裁决溯源。
	Attrs map[string]Attribute
	// VulnIDs / CredIDs 是关系图中挂在该服务下的节点 ID。
	VulnIDs []string
	CredIDs []string
}

// Vuln 是收敛后的漏洞节点。
type Vuln struct {
	ID         string
	Title      string
	Severity   string
	Source     string
	Attributes map[string]string
}

// WeakCred 是收敛后的弱口令节点。
type WeakCred struct {
	ID       string
	Port     int
	Username string
	AuthType string
	Detail   string
	Source   string
}

// Asset 是去重收敛后的唯一资产。
type Asset struct {
	ID        string // 内部组件标识
	PrimaryID string // 对外稳定标识
	IPNets    []string
	Hostnames []string
	OS        Attribute
	Domain    Attribute
	// Lists 保存多值属性（hostnames/ipnets）每个值的来源依据。
	Lists    map[string][]ValueProvenance
	Services map[string]*Service
	Vulns    map[string]*Vuln // 资产级漏洞
	Creds    map[string]*WeakCred
	Version  int64
}

// EdgeKind 枚举关系图边类型。
type EdgeKind string

const (
	EdgeAssetService EdgeKind = "asset->service"
	EdgeServiceVuln  EdgeKind = "service->vuln"
	EdgeServiceCred  EdgeKind = "service->weakcred"
	EdgeAssetVuln    EdgeKind = "asset->vuln"
	EdgeAssetDomain  EdgeKind = "asset->domain"
)

// Edge 是关系图中的一条有向边。
type Edge struct {
	From string   `json:"from"`
	To   string   `json:"to"`
	Kind EdgeKind `json:"kind"`
}
