package source

import (
	"context"
	"time"

	"github.com/shikejing/asset-inventory-graph-go/model"
)

// SimSource 内存模拟扫描来源：通过 Go channel 产出记录，
// 可注入每条记录的延迟来模拟慢来源（整条链路不依赖外部服务）。
type SimSource struct {
	name    string
	records []model.RawRecord
	delay   time.Duration
	jitter  func(int) time.Duration
}

// NewSimSource 构造内存模拟来源。
func NewSimSource(name string, records []model.RawRecord) *SimSource {
	cp := make([]model.RawRecord, len(records))
	copy(cp, records)
	return &SimSource{name: name, records: cp}
}

// WithDelay 设置每条记录发送前的固定延迟。
func (s *SimSource) WithDelay(d time.Duration) *SimSource { s.delay = d; return s }

// WithJitter 设置按序号变化的额外延迟。
func (s *SimSource) WithJitter(f func(int) time.Duration) *SimSource { s.jitter = f; return s }

func (s *SimSource) Name() string { return s.name }

func (s *SimSource) Records(ctx context.Context) <-chan model.RawRecord {
	ch := make(chan model.RawRecord)
	go func() {
		defer close(ch)
		for i, r := range s.records {
			d := s.delay
			if s.jitter != nil {
				d += s.jitter(i)
			}
			if d > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(d):
				}
			}
			select {
			case <-ctx.Done():
				return
			case ch <- r:
			}
		}
	}()
	return ch
}
