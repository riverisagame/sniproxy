// package proxy 实现了 SNI 代理的核心——"接收连接 → 解析SNI → 转发到后端"。
//
// 这个包的架构可以用一个比喻来理解：
//
//   你走进一家"万能银行"的大厅：
//   1. 你(客户端)走到前台,告诉工作人员你想办什么业务(发送 TLS ClientHello)
//   2. 工作人员看一眼你的需求——哦,你是来办信用卡的(解析 SNI 域名)
//   3. 工作人员告诉你"信用卡业务在3楼2号窗口"(路由查找后端地址)
//   4. 工作人员把你直接连到3楼2号窗口,然后你和窗口之间的对话就畅通无阻了(双向转发)
//
// 关键特点：
//   - 透明代理：不解密 TLS 流量,只是看一眼 SNI 域名然后原样转发
//   - 零拷贝：在 Linux 上使用 splice 系统调用,数据在内核空间直接拷贝,
//             无需经过用户空间,性能极高
//   - 长连接支持：设置 TCP KeepAlive,防止空闲连接被中间路由器断开
package proxy

import (
	"context"     // 用于接收"停止工作"的信号
	"fmt"         // 格式化，用于 panic recovery
	"io"          // 输入输出操作,这里用 io.ReadFull(读满)、io.Copy(拷贝数据)
	"log/slog"    // 结构化日志
	"math/rand"   // 随机数,用于静默丢弃时加入时间抖动
	"net"         // 网络操作：Dial(连接)、Listen(监听)、TCPConn(TCP 连接对象)
	"sync"        // sync.Pool 复用 TLS 缓冲区
	"sync/atomic" // 原子操作,用于热加载路由表
	"time"        // 时间相关：超时、计时

	"sniproxy/internal/router" // 我们的路由器,用于 SNI → 后端的查找
	"sniproxy/internal/sni"    // 我们的 SNI 解析器,从 ClientHello 中提取域名
)

// 以下是代理用到的三个超时/间隔常量：
const (
	// peekTimeout："窥探"超时——读取 ClientHello 的最长等待时间(30秒)
	// 相当于"你走进银行后,最多给你30秒说明来意,超时就请出去"。
	// 这是防止"慢速攻击"——恶意客户端故意很慢地发送数据,消耗服务器资源。
	peekTimeout = 30 * time.Second

	// dialTimeout：连接后端服务器的超时时间(10秒)
	// 相当于"拨通3楼2号窗口的内部电话,最多等10秒"。
	// 如果后端服务器宕机或网络不通,10秒后就不再等待。
	dialTimeout = 10 * time.Second

	// keepAliveIdle：TCP KeepAlive 的探测间隔(15秒)
	// TCP KeepAlive 是什么？
	// 正常情况下,如果一方断网,另一方可能很久都不知道。
	// KeepAlive 就是每15秒发一个"心跳检测包"问对方"你还活着吗？"
	// 如果连续几次没回应,就认为连接断了,释放资源。
	// 这就像两个人在打电话,每15秒说一声"喂,还在吗？"
	keepAliveIdle = 15 * time.Second

	idleTimeout = 5 * time.Minute
)

// tlsBufPool 复用 TLS 记录缓冲区，消除每个连接 ~16KB 的堆分配。
// 高并发下(1w+ qps)可显著降低 GC 压力。
var tlsBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 5+16384) // 头 + 最大 TLS 记录
		return &buf
	},
}

var connCounter atomic.Uint64

// RouterRef 持有一个原子指针指向当前的路由表,支持热加载。
// SIGHUP 信号触发配置重载时,新的 Router 通过 Store 写入,
// 所有后续连接自动使用新规则。
type RouterRef struct {
	r atomic.Pointer[router.Router]
}

func NewRouterRef(r *router.Router) *RouterRef {
	ref := &RouterRef{}
	ref.r.Store(r)
	return ref
}

func (ref *RouterRef) Load() *router.Router { return ref.r.Load() }
func (ref *RouterRef) Store(r *router.Router) { ref.r.Store(r) }

// AcceptLoop 是代理的"主循环"——无限等待新连接,每来一个就开一个 goroutine 处理。
//
// 参数：
//   ctx    - 上下文,当 ctx 被取消时(收到关闭信号),AcceptLoop 会优雅退出
//   ln     - 网络监听器,相当于"营业大厅的入口大门"
//   r      - 路由器,用于 SNI 域名 → 后端地址的查找
//   logger - 日志记录器
//
// 返回值：
//   error - 正常退出(因为 ctx 取消)返回 nil；
//           异常退出返回错误信息
//
// 关于 goroutine：
//   Go 语言的 goroutine 是"轻量级线程"——每个 goroutine 只占用几 KB 内存。
//   所以即使同时有几千个连接,每个连接启动一个 goroutine 也毫无压力。
//   这就像一个银行有几千个工作人员,每个顾客进来都能分到一个专人服务。
func AcceptLoop(ctx context.Context, ln net.Listener, ref *RouterRef, maxConns int, logger *slog.Logger) error {
	// 连接准入控制：带缓冲 channel 做信号量，maxConns=0 表示不限制
	var sem chan struct{}
	if maxConns > 0 {
		sem = make(chan struct{}, maxConns)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				logger.Error("accept failed", "error", err)
				continue
			}
		}

		if sem != nil {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				conn.Close()
				return nil
			}
		}

		go func() {
			handleConnection(ctx, conn, ref, logger)
			if sem != nil {
				<-sem
			}
		}()
	}
}

// handleConnection 处理一个客户端连接的全过程。
//
// 这是代理最核心的函数。它完成以下步骤：
//
//   步骤1：读取 TLS 记录头(5字节) → 确认是 TLS 握手
//   步骤2：读取完整的 TLS 记录    → 把整个 ClientHello 读进内存
//   步骤3：解析 SNI 域名          → 从 ClientHello 中提取出目标域名
//   步骤4：路由查找               → 根据域名查找对应的后端地址
//   步骤5：清除超时限制           → 后续的转发不限时(长连接)
//   步骤6：连接后端服务器         → 建立到后端的 TCP 连接
//   步骤7：开启 TCP KeepAlive     → 防止空闲断开
//   步骤8：重放 ClientHello       → 把客户端发来的数据原样发给后端
//   步骤9：双向转发               → 两个 goroutine 各自负责一个方向的数据拷贝
func handleConnection(ctx context.Context, clientConn net.Conn, ref *RouterRef, logger *slog.Logger) {
	defer clientConn.Close()

	defer func() {
		if r := recover(); r != nil {
			logger.Error("connection handler panic", "remote", clientConn.RemoteAddr(), "panic", fmt.Sprint(r))
		}
	}()

	// 获取客户端地址(IP:端口),用于日志记录
	remote := clientConn.RemoteAddr().String()

	// ============================================================
	// 类型断言：检查这个连接是否是 TCP 连接(TCPConn)
	// net.Conn 是一个"接口",可以是 TCP/Unix 等任何类型
	// 我们只处理 TCP 连接,因为需要 TCP 特有的功能(splice 等)
	// ============================================================
	tcpConn, ok := clientConn.(*net.TCPConn)
	if !ok {
		logger.Debug("not a TCP connection", "remote", remote)
		return
	}

	// ============================================================
	// 步骤1：设置读取超时 + 读取 TLS 记录头(5字节)
	//
	// SetReadDeadline 是什么？
	// 设置一个"截止时间",如果在这个时间之前没有读到数据,
	// Read 会返回超时错误。这防止恶意客户端故意慢慢发数据。
	//
	// TLS 记录头结构(回顾)：
	//   [0]    = 0x16(Handshake 类型)
	//   [1:2]  = TLS 版本(我们不太关心)
	//   [3:4]  = 记录体长度(大端序)
	// ============================================================

	if err := tcpConn.SetReadDeadline(time.Now().Add(peekTimeout)); err != nil {
		logger.Debug("set read deadline failed", "remote", remote, "error", err)
		return
	}

	// 从池中获取可复用的 TLS 记录缓冲区,避免每次分配 ~16KB
	bufPtr := tlsBufPool.Get().(*[]byte)
	buf := *bufPtr

	// 读取 TLS 记录头(5字节) 到池缓冲区的前5字节
	if _, err := io.ReadFull(tcpConn, buf[:5]); err != nil {
		tlsBufPool.Put(bufPtr)
		logger.Debug("read TLS header failed", "remote", remote, "error", err)
		return
	}

	if buf[0] != 0x16 {
		tlsBufPool.Put(bufPtr)
		logger.Debug("not a TLS handshake", "remote", remote, "type", buf[0])
		return
	}

	recordLen := int(buf[3])<<8 | int(buf[4])

	if recordLen < 2 || recordLen > 16384 {
		tlsBufPool.Put(bufPtr)
		logger.Debug("invalid TLS record length", "remote", remote, "len", recordLen)
		return
	}

	// 读取完整的 TLS 记录体到 buf[5:]
	totalLen := 5 + recordLen
	buf = buf[:totalLen]
	if _, err := io.ReadFull(tcpConn, buf[5:]); err != nil {
		tlsBufPool.Put(bufPtr)
		logger.Debug("read TLS record body failed", "remote", remote, "error", err)
		return
	}

	// ============================================================
	// 步骤3：解析 SNI 域名
	// 调用我们写的 sni.Parse 函数从完整的 TLS 记录中提取域名
	// ============================================================

	sniBytes, err := sni.ParseBytes(buf)
	if err != nil {
		tlsBufPool.Put(bufPtr)
		logger.Debug("SNI parse failed", "remote", remote, "error", err)
		return
	}

	backend := ref.Load().LookupBytes(sniBytes)
	sniHost := string(sniBytes)
	if backend == "" {
		tlsBufPool.Put(bufPtr)
		stealthDrop(ctx, tcpConn, logger, remote, sniHost)
		return
	}
	logger.Debug("SNI route", "remote", remote, "sni", sniHost, "backend", backend)

	// ============================================================
	// 步骤5：清除读取超时
	// 前面的超时是为了防止客户端不发数据占着连接
	// 现在已经确定了要转发,后续的数据传输应该是"不限时"的
	// time.Time{} 是 Go 里"零值",表示"没有截止时间"
	// ============================================================

	tcpConn.SetDeadline(time.Time{})

	// ============================================================
	// 步骤6：连接到后端服务器
	// net.DialTimeout 类似于"打电话给后端服务器",最长等 dialTimeout(10秒)
	// ============================================================

	backendConn, err := net.DialTimeout("tcp", backend, dialTimeout)
	if err != nil {
		logger.Error("backend dial failed", "remote", remote, "sni", sniHost, "backend", backend, "error", err)
		return
	}
	defer backendConn.Close()

	// 确认后端连接也是 TCP 类型
	btcpConn, ok := backendConn.(*net.TCPConn)
	if !ok {
		logger.Debug("backend not a TCP connection", "remote", remote)
		return
	}

	// ============================================================
	// 步骤7：调优 socket 缓冲区 + TCP KeepAlive
	// ============================================================

	setSocketBuf(tcpConn, logger)
	setSocketBuf(btcpConn, logger)
	setKeepAlive(tcpConn)
	setKeepAlive(btcpConn)

	// 记录连接建立成功的日志
	logger.Debug("connected", "remote", remote, "sni", sniHost, "backend", backend)

	n := connCounter.Add(1)
	if n%1000 == 0 {
		logger.Info("connection sample", "count", n, "remote", remote, "sni", sniHost, "backend", backend)
	}

	// ============================================================
	// 步骤8：重放 ClientHello 到后端
	// 把之前从客户端收到的 TLS 记录原封不动地发给后端
	// 后端收到的数据跟客户端直接连接它时完全一样——这就是"透明代理"
	// 后端不会意识到中间有个代理在转发
	// ============================================================

	if _, err := backendConn.Write(buf); err != nil {
		tlsBufPool.Put(bufPtr)
		logger.Debug("replay ClientHello failed", "remote", remote, "error", err)
		return
	}
	tlsBufPool.Put(bufPtr) // buffer no longer needed after replay

	if err := tcpConn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
		logger.Debug("set idle timeout on client", "remote", remote, "error", err)
	}
	if err := btcpConn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
		logger.Debug("set idle timeout on backend", "remote", remote, "error", err)
	}

	// ============================================================
	// 步骤9：双向转发数据
	//
	// 从现在开始,客户端和后端之间进入"自由对话"模式。
	// 代理就像一根透明的管道,数据在两个方向上自由流动：
	//
	//   客户端 → [你收到的数据] → 后端
	//   客户端 ← [后端返回的数据] ← 后端
	//
	// 用两个 goroutine 各负责一个方向：
	//   - goroutine A：客户端→后端(我们叫 rx 方向,即"接收"方向)
	//   - goroutine B：后端→客户端(我们叫 tx 方向,即"发送"方向)
	//
	// 在 Linux 上,Go 的 io.Copy 会自动使用 splice(2) 系统调用：
	//   splice 允许数据在内核空间直接从一个 socket 拷贝到另一个,
	//   不需要经过用户空间(应用程序内存),性能非常高,CPU 占用极低。
	//
	// 这是本项目最关键的性能优化——"零拷贝转发"。
	// ============================================================

	start := time.Now()        // 记录转发开始时间,用于最后的统计
	var rx, tx int64           // rx = 客户端发来的总字节数, tx = 后端返回的总字节数

	// 用 WaitGroup 替代 per-connection channel，消除堆分配
	var wg sync.WaitGroup
	wg.Add(2)

	// goroutine A：客户端 → 后端(rx 方向)
	go func() {
		defer wg.Done()
		n, err := io.Copy(btcpConn, tcpConn)
		rx = n
		if err != nil {
			logger.Debug("copy client->backend", "remote", remote, "sni", sniHost, "error", err)
		}
	}()

	// goroutine B：后端 → 客户端(tx 方向)
	go func() {
		defer wg.Done()
		n, err := io.Copy(tcpConn, btcpConn)
		tx = n
		if err != nil {
			logger.Debug("copy backend->client", "remote", remote, "sni", sniHost, "error", err)
		}
	}()

	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	// 等待两个方向都完成，或收到关闭信号
	select {
	case <-doneCh:
		// 两个方向都完成了
	case <-ctx.Done():
		// 收到关闭信号——关闭两端连接，让 io.Copy 立即返回
		tcpConn.Close()
		btcpConn.Close()
	}
	<-doneCh

	// 记录连接的"结账信息"：
	//   rx   = 客户端发来了多少字节
	//   tx   = 后端返回了多少字节
	//   dur  = 连接持续了多长时间
	dur := time.Since(start)
	logger.Debug("close", "remote", remote, "sni", sniHost, "rx", rx, "tx", tx, "dur", dur.Round(time.Millisecond).String())
}

// setKeepAlive 为一个 TCP 连接开启"心跳检测"。
//
// TCP KeepAlive 做了什么？
// 正常情况下,TCP 连接建立后,即使长时间没有数据传输,连接也不会断。
// 但实际网络中存在各种中间设备(路由器、NAT 网关、防火墙),
// 它们可能会清理"看起来不活跃"的连接。
//
// KeepAlive 就是定期发送一个空的"探测包"到对方：
//   - 如果对方存在且连接正常 → 对方回复 ACK,"我知道你还在"
//   - 如果对方已经断开(网络断了/程序崩溃) → 连续几次没回复,操作系统关闭连接
//
// SetKeepAlive(true) → 开启"心跳检测"
// SetKeepAlivePeriod(15s) → 每15秒发送一次心跳
func setSocketBuf(conn *net.TCPConn, logger *slog.Logger) {
	if err := conn.SetReadBuffer(256 * 1024); err != nil {
		logger.Warn("set read buffer failed", "error", err)
	}
	if err := conn.SetWriteBuffer(256 * 1024); err != nil {
		logger.Warn("set write buffer failed", "error", err)
	}
}

func setKeepAlive(conn *net.TCPConn) {
	conn.SetKeepAlive(true)               // 开启 KeepAlive
	conn.SetKeepAlivePeriod(keepAliveIdle) // 心跳间隔 = 15秒
}

// stealthDrop 静默丢弃不匹配的 SNI 连接。
// 不发送任何 TLS 响应和 TCP RST,客户端只会感知到超时,
// 与"防火墙丢包"或"端口无服务"无法区分。
func stealthDrop(ctx context.Context, conn *net.TCPConn, logger *slog.Logger, remote, sni string) {
	logger.Debug("sni dropped (no match)", "remote", remote, "sni", sni)

	// 随机抖动 4~6 秒,避免固定延时被用于指纹识别
	holdTime := 4*time.Second + time.Duration(rand.Int63n(2000))*time.Millisecond
	if err := conn.SetReadDeadline(time.Now().Add(holdTime)); err != nil {
		logger.Debug("stealth drop set deadline failed", "remote", remote, "error", err)
	}

	select {
	case <-time.After(holdTime):
	case <-ctx.Done():
	}
}
