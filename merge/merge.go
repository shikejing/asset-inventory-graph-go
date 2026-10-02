package merge

import (
	"sort"

	"github.com/shikejing/asset-inventory-graph-go/model"
)

// Strategy 是属性冲突合并策略。
type Strategy string

const (
	// StrategySourcePriority：高优先级来源胜出；同优先级取最新时间戳；
	// 再相同则取值字典序最小者。比较器是全序的，保证结果与到达顺序无关。
	StrategySourcePriority Strategy = "source_priority"
	// StrategyLatest：最新时间戳胜出，其余按优先级、值兜底。
	StrategyLatest Strategy = "latest"
	// StrategyMergeSet：多值集合合并，每个值保留全部来源依据。
	StrategyMergeSet Strategy = "merge_set"
)

// Config 定义来源优先级与各属性的合并规则。
type Config struct {
	// SourcePriority: 数值越大优先级越高；未列出的来源优先级为 0。
	SourcePriority  map[string]int
	Strategies      map[string]Strategy
	DefaultStrategy Strategy
}

// DefaultConfig 给出缺省规则。
func DefaultConfig() Config {
	return Config{
		SourcePriority: map[string]int{
			"cmdb":        100,
			"agent":       90,
			"nmap":        50,
			"passivescan": 30,
		},
		Strategies: map[string]Strategy{
			"os":          StrategySourcePriority,
			"domain":      StrategySourcePriority,
			"hostnames":   StrategyMergeSet,
			"ipnets":      StrategyMergeSet,
			"svc.name":    StrategySourcePriority,
			"svc.version": StrategyLatest,
			"svc.product": StrategySourcePriority,
			"svc.banner":  StrategyLatest,
		},
		DefaultStrategy: StrategySourcePriority,
	}
}

// Merger 负责属性冲突裁决。
type Merger struct{ cfg Config }

func NewMerger(cfg Config) *Merger {
	if cfg.SourcePriority == nil {
		cfg.SourcePriority = map[string]int{}
	}
	if cfg.Strategies == nil {
		cfg.Strategies = map[string]Strategy{}
	}
	if cfg.DefaultStrategy == "" {
		cfg.DefaultStrategy = StrategySourcePriority
	}
	return &Merger{cfg: cfg}
}

// StrategyFor 返回属性键使用的策略。
func (m *Merger) StrategyFor(key string) Strategy {
	if s, ok := m.cfg.Strategies[key]; ok {
		return s
	}
	return m.cfg.DefaultStrategy
}

// less 定义来源观察的全序：返回 a 是否应当排在 b 前面（a 更优）。
func (m *Merger) better(a, b model.Provenance) bool {
	pa := m.cfg.SourcePriority[a.Source]
	pb := m.cfg.SourcePriority[b.Source]
	if pa != pb {
		return pa > pb
	}
	if a.Timestamp != b.Timestamp {
		return a.Timestamp > b.Timestamp
	}
	return a.Value < b.Value // 最终确定性兜底
}

func (m *Merger) betterByTime(a, b model.Provenance) bool {
	if a.Timestamp != b.Timestamp {
		return a.Timestamp > b.Timestamp
	}
	return m.better(a, b)
}

// MergeScalar 将多次来源观察裁决为单一属性，保留全部依据。
// 相同 (source,value) 的重复观察只保留一条（取更新时间戳）。
func (m *Merger) MergeScalar(key string, provs []model.Provenance) model.Attribute {
	strat := m.StrategyFor(key)
	uniq := dedupProv(provs)
	by := m.better
	if strat == StrategyLatest {
		by = m.betterByTime
	}
	sort.SliceStable(uniq, func(i, j int) bool { return by(uniq[i], uniq[j]) })
	attr := model.Attribute{Key: key, Strategy: string(strat)}
	if len(uniq) == 0 {
		return attr
	}
	attr.Winner = uniq[0]
	attr.Value = uniq[0].Value
	// History 以裁决顺序保留全部来源依据；重复应用同一批输入结果不变。
	attr.History = uniq
	return attr
}

// MergeSet 多值集合合并：按值分组，每值记录全部来源依据；结果按值排序。
func (m *Merger) MergeSet(key string, provs []model.Provenance) []model.ValueProvenance {
	group := map[string][]model.Provenance{}
	for _, p := range dedupProv(provs) {
		group[p.Value] = append(group[p.Value], p)
	}
	out := make([]model.ValueProvenance, 0, len(group))
	for val, ps := range group {
		sort.SliceStable(ps, func(i, j int) bool { return m.better(ps[i], ps[j]) })
		out = append(out, model.ValueProvenance{Value: val, Sources: ps})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

// dedupProv 对相同 (source, value) 的观察去重，保留时间戳最新的一条。
func dedupProv(provs []model.Provenance) []model.Provenance {
	type kv struct {
		source, value string
	}
	best := map[kv]model.Provenance{}
	order := []kv{}
	for _, p := range provs {
		k := kv{p.Source, p.Value}
		if cur, ok := best[k]; !ok {
			best[k] = p
			order = append(order, k)
		} else if p.Timestamp > cur.Timestamp {
			best[k] = p
		}
	}
	out := make([]model.Provenance, 0, len(order))
	for _, k := range order {
		out = append(out, best[k])
	}
	return out
}
