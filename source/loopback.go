package source

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/shikejing/asset-inventory-graph-go/model"
)

// LoopbackServer 是监听本地回环地址的扫描数据接收端。
// 来源进程通过 TCP 发送按行分隔的 JSON RawRecord，不依赖任何外部服务。
type LoopbackServer struct {
	ln   net.Listener
	ch   chan model.RawRecord
	done chan struct{}
	wg   sync.WaitGroup
	once sync.Once
}

// NewLoopbackServer 在 127.0.0.1 上启动监听，port=0 时由系统分配端口。
func NewLoopbackServer(port int) (*LoopbackServer, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	s := &LoopbackServer{ln: ln, ch: make(chan model.RawRecord, 64), done: make(chan struct{})}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

func (s *LoopbackServer) Addr() string { return s.ln.Addr().String() }

func (s *LoopbackServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer c.Close()
			sc := bufio.NewScanner(c)
			sc.Buffer(make([]byte, 1024*1024), 32*1024*1024)
			for sc.Scan() {
				var rec model.RawRecord
				if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
					continue
				}
				// 先收进内部缓冲，不依赖消费者何时开始，避免与发送方形成时序死锁。
				select {
				case s.ch <- rec:
				case <-s.done:
					return
				default:
					// 缓冲满时阻塞等待消费或关闭。
					select {
					case s.ch <- rec:
					case <-s.done:
						return
					}
				}
			}
		}(conn)
	}
}

// Records 实现 Source。idle 表示最后一条记录到达后多久自动结束流
// （0 表示不超时，等待 ctx 取消或 Close）。批量推送型来源可用较小的 idle。
func (s *LoopbackServer) Records(ctx context.Context, idle ...time.Duration) <-chan model.RawRecord {
	var idleTo time.Duration
	if len(idle) > 0 {
		idleTo = idle[0]
	}
	out := make(chan model.RawRecord)
	go func() {
		defer close(out)
		var timer *time.Timer
		var timerC <-chan time.Time
		reset := func() {
			if idleTo <= 0 {
				return
			}
			if timer == nil {
				timer = time.NewTimer(idleTo)
				timerC = timer.C
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(idleTo)
			}
		}
		reset()
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.done:
				return
			case <-timerC:
				return
			case r := <-s.ch:
				reset()
				select {
				case <-ctx.Done():
					return
				case out <- r:
				}
			}
		}
	}()
	return out
}

// Name 实现 Source。
func (s *LoopbackServer) Name() string { return "loopback://" + s.Addr() }

// Close 停止监听并解除所有阻塞。
func (s *LoopbackServer) Close() error {
	var err error
	s.once.Do(func() {
		close(s.done)
		err = s.ln.Close()
	})
	s.wg.Wait()
	return err
}

// SendLoopback 连接回环服务端并发送一批记录（按行 JSON 编码）。
func SendLoopback(addr string, recs []model.RawRecord) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	enc := json.NewEncoder(conn)
	for i := range recs {
		if err := enc.Encode(recs[i]); err != nil {
			return err
		}
	}
	return nil
}
