package source

import (
	"context"
	"sync"

	"github.com/shikejing/asset-inventory-graph-go/model"
)

// Ingester 是 Runner 需要的摄入能力（由 *engine.Engine 满足）。
type Ingester interface {
	IngestBatch(rs []model.RawRecord) (int, error)
	Ingest(r model.RawRecord) error
}

// Source 是扫描来源接口。
type Source interface {
	Name() string
	Records(ctx context.Context) <-chan model.RawRecord
}

// Runner 并发驱动多个来源摄入引擎。
type Runner struct {
	ing Ingester
}

// NewRunner 构造 Runner。
func NewRunner(ing Ingester) *Runner { return &Runner{ing: ing} }

type sourced struct {
	source string
	rec    model.RawRecord
}

// Run 并发拉取全部来源并幂等摄入。
// 设计为 fan-in：每个来源只做“读 channel -> 转发”，绝不执行可能阻塞的提交；
// 提交在主循环中按批进行。这样：
//   - 慢来源只延迟自己的数据，不阻塞其它来源与查询推进；
//   - fsync/锁等待期间来源仍可继续排空并关闭，不会死锁。
func (r *Runner) Run(ctx context.Context, sources []Source) error {
	in := make(chan sourced, 256)
	var wg sync.WaitGroup
	for _, src := range sources {
		wg.Add(1)
		go func(src Source) {
			defer wg.Done()
			recs := src.Records(ctx)
			for {
				select {
				case <-ctx.Done():
					return
				case rec, ok := <-recs:
					if !ok {
						return
					}
					select {
					case in <- sourced{source: src.Name(), rec: rec}:
					case <-ctx.Done():
						return
					}
				}
			}
		}(src)
	}
	go func() { wg.Wait(); close(in) }()

	var first error
	var batch []model.RawRecord
	flush := func() {
		if len(batch) == 0 || first != nil {
			batch = batch[:0]
			return
		}
		if _, err := r.ing.IngestBatch(batch); err != nil && first == nil {
			first = err
		}
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			if first != nil {
				return first
			}
			return ctx.Err()
		case item, ok := <-in:
			if !ok {
				flush()
				return first
			}
			batch = append(batch, item.rec)
			if len(batch) >= 32 {
				flush()
			}
		}
	}
}
