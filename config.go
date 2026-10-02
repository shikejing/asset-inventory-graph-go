package inventory

// MergeStrategy defines how a single-valued attribute is resolved when
// sources disagree.
type MergeStrategy string

const (
	// StrategyPriority picks the value from the highest-priority source.
	// Ties are broken by recency, then by source id for determinism.
	StrategyPriority MergeStrategy = "priority"
	// StrategyLatest picks the value with the newest observation timestamp.
	StrategyLatest MergeStrategy = "latest"
	// StrategyFirst picks the earliest observed value.
	StrategyFirst MergeStrategy = "first"
	// StrategyUnion collects every observed value (used for multi-valued
	// attributes such as ports and services).
	StrategyUnion MergeStrategy = "union"
)

// Config controls merge behaviour and persistence.
type Config struct {
	// DataDir holds the write-ahead log and snapshot files.
	DataDir string

	// SourcePriority maps a source to its priority; higher wins.
	// Sources absent from the map default to priority 0.
	SourcePriority map[SourceID]int

	// MergeRules selects a strategy per attribute name
	// (e.g. "hostname", "os", "domain", "version", "attr.<name>").
	// Attributes without an explicit rule use DefaultStrategy.
	MergeRules map[string]MergeStrategy

	// DefaultStrategy is used for attributes without an explicit rule.
	DefaultStrategy MergeStrategy

	// SnapshotEvery controls how many committed records are applied between
	// automatic snapshots.
	SnapshotEvery int
}

// DefaultConfig returns a usable configuration with sensible defaults.
func DefaultConfig() Config {
	return Config{
		DataDir:        "./inventory-data",
		SourcePriority: map[SourceID]int{},
		MergeRules: map[string]MergeStrategy{
			// Hostname is a stable identity claim: prefer the earliest
			// observed value so it does not flip-flop between sources.
			"hostname": StrategyFirst,
			// Everything else follows source priority by default.
		},
		DefaultStrategy: StrategyPriority,
		SnapshotEvery:   50,
	}
}

func (c Config) strategyFor(attr string) MergeStrategy {
	if c.MergeRules != nil {
		if s, ok := c.MergeRules[attr]; ok {
			return s
		}
	}
	return c.DefaultStrategy
}

func (c Config) priorityOf(s SourceID) int {
	if c.SourcePriority != nil {
		if p, ok := c.SourcePriority[s]; ok {
			return p
		}
	}
	return 0
}
