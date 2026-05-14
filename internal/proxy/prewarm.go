package proxy

import (
	"context"  // 上下文，用于响应 shutdown 信号
	"log/slog" // 结构化日志
	"net"      // 网络操作：DialTimeout(带超时的连接)
	"sync"     // 同步原语：WaitGroup(等待一组 goroutine 完成)
	"time"     // 时间相关：超时

	"sniproxy/internal/router" // 路由器,用于获取所有后端地址列表
)

// PreWarm 在代理启动时"预热"所有后端连接。
//
// 为什么需要"预热"？
// 1. 提前验证——确认所有后端服务器都能连上
//    （如果有后端宕机,启动时就打印警告,方便运维人员发现）
// 2. 预热内核的连接跟踪表(conntrack)——
//    Linux 内核会记录每个网络连接的"状态"(NEW/ESTABLISHED/CLOSED等),
//    第一次连接时需要创建跟踪条目,有一点开销。
//    提前连一次相当于"热了热身",正式请求时会更快。
//
// 类比：
//   餐厅开业前,厨师先试做一遍所有菜品——
//   既确认了食材和工具都没问题,又提前"热身"了厨房设备。
//
// 参数：
//   r       - 路由器,通过 UniqueBackends() 获取所有不重复的后端地址
//   timeout - 每个后端连接的超时时间(建议5秒)
//   logger  - 日志记录器
//
// 预热是"尽力而为"的——某个后端连不上只会打印警告,
// 不会阻止代理启动。因为后端可能只是暂时离线,等等就好了。
func PreWarm(ctx context.Context, r *router.Router, timeout time.Duration, logger *slog.Logger) {
	backends := r.UniqueBackends()
	if len(backends) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, addr := range backends {
		// 收到 shutdown 信号时停止后续预热
		select {
		case <-ctx.Done():
			wg.Wait() // 等待已启动的预热完成
			return
		default:
		}

		wg.Add(1)
		go func(addr string) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				logger.Warn("backend pre-warm failed", "addr", addr, "error", err)
				return
			}
			conn.Close()
			logger.Info("backend pre-warm OK", "addr", addr)
		}(addr)
	}

	wg.Wait()
}
