// package main 是这个程序的"入口包"。
// 在 Go 语言中,main 包里的 main() 函数是整个程序启动时第一个被执行的函数,
// 就像电影的"第一幕",一切从这里开始。
package main

import (
	"context"    // 用于传递"取消信号"——比如用户按 Ctrl+C 时通知所有工作停止
	"flag"       // 用于解析命令行参数,比如 -c /etc/config.yaml
	"fmt"        // 格式化输入输出,类似 Python 的 print()
	"log/slog"   // Go 1.21+ 自带的结构化日志库,记录程序运行时的各种信息
	"net"        // 网络操作的核心库,提供 Listen(监听)、Accept(接受连接)、Dial(拨号连接)
	"net/http"   // HTTP 服务,用于 pprof 调试端点
	_ "net/http/pprof" // pprof 性能分析,自动注册 /debug/pprof/ 路径
	"os"         // 操作系统相关操作,比如读取环境变量、退出程序
	"os/signal"  // 监听操作系统发来的"信号",比如 Ctrl+C(SIGINT)、SIGHUP(重新加载配置)
	"sync/atomic" // 原子操作,用于并发安全的日志级别切换
	"syscall"     // 低层系统调用,这里用来定义 SIGHUP 等信号常量的具体值
	"time"        // 时间相关操作,比如设置超时

	"sniproxy/internal/config" // 我们自己写的配置加载模块
	"sniproxy/internal/proxy"  // 我们自己写的代理核心模块
)

// toggleSignal 是一个变量,存储用于"切换日志级别"的操作系统信号。
// 在 Linux 上是 SIGUSR1(用户自定义信号1),
// 在 Windows 上没有对应信号,所以是 nil(空)。
// 这行代码会在 platform_linux.go 或 platform_windows.go 的 init() 函数中被赋值。
var toggleSignal os.Signal

// atomicLevel 实现 slog.Leveler 接口,支持并发安全的日志级别切换。
// slog.HandlerOptions.Level 字段在每个日志调用时都会读取,
// 直接用 slog.Level 值在多个 goroutine 间读写会触发 data race。
type atomicLevel struct {
	level atomic.Int32
}

func (a *atomicLevel) Level() slog.Level { return slog.Level(a.level.Load()) }
func (a *atomicLevel) Set(l slog.Level)   { a.level.Store(int32(l)) }

func newAtomicLevel(l slog.Level) *atomicLevel {
	a := &atomicLevel{}
	a.level.Store(int32(l))
	return a
}

// parseLogLevel 把配置文件中的字符串转换成 slog.Level。
// 合法值已在 config.Load 中校验，这里不会收到无效值。
func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	default:
		return slog.LevelError
	}
}

// main() 是程序的入口函数。当你运行 ./sniproxy 时,这个函数第一个执行。
func main() {
	// ============================================================
	// 第一部分：定义和解析命令行参数
	// 命令行参数让你在启动程序时传递配置,比如：./sniproxy -c myconfig.yaml -vv
	// ============================================================

	// -c 参数：指定配置文件路径,默认值是 /etc/sniproxy/config.yaml
	configPath := flag.String("c", "/etc/sniproxy/config.yaml", "config file path")
	// -d 参数：是否以守护进程(后台服务)方式运行,默认 false
	daemonize := flag.Bool("d", false, "run as daemon (background)")
	// 日志详细程度,0=只显示错误, 1=信息级别, 2/3=调试级别
	verbosity := 0
	// -v：显示信息级别日志（比默认的"只显示错误"更详细）
	flag.BoolFunc("v", "info log level", func(string) error { verbosity = max(verbosity, 1); return nil })
	// -vv：显示调试级别日志（最详细,用于排查问题）
	flag.BoolFunc("vv", "debug log level", func(string) error { verbosity = max(verbosity, 2); return nil })
	// -vvv：调试级别 + 额外打印配置内容
	flag.BoolFunc("vvv", "debug log level + dump config", func(string) error { verbosity = max(verbosity, 3); return nil })
	// --log-format：日志输出格式,"text"(人类可读) 或 "json"(机器可读)
	logFormat := flag.String("log-format", "text", "log format: text or json")
	// --log-file：日志写入文件路径,默认空表示输出到终端(标准输出)
	logFile := flag.String("log-file", "", "log file path (default: stdout)")
	flag.Parse() // 真正解析命令行,这一行之后上面的变量才有值

	// ============================================================
	// 第二部分：加载配置文件
	// 配置文件(YAML格式)定义了"监听哪个端口"和"把请求转发到哪些后端服务器"
	// ============================================================

	cfg, err := config.Load(*configPath) // 读 YAML 文件,解析成 Config 结构体
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config failed: %v\n", err)
		os.Exit(1)
	}

	// ============================================================
	// 第三部分：初始化日志系统
	// 日志就是程序在运行过程中"写日记",记录发生了什么。
	// 好的日志让你能知道程序在干什么、出了什么问题。
	// ============================================================

	// 优先级：CLI 参数 > 配置文件 > 默认值
	level := parseLogLevel(cfg.LogLevel) // 配置文件值（默认 "error"）
	if verbosity >= 1 {
		level = slog.LevelInfo
	}
	if verbosity >= 2 {
		level = slog.LevelDebug
	}
	logPath := *logFile
	if logPath == "" {
		logPath = cfg.LogFile
	}

	if *daemonize && logPath == "" {
		logPath = "/var/log/sniproxy/sniproxy.log"
		if err := os.MkdirAll("/var/log/sniproxy", 0755); err != nil {
			fmt.Fprintf(os.Stderr, "create log dir: %v\n", err)
			os.Exit(1)
		}
	}

	logLeveler := newAtomicLevel(level)
	handlerOpts := &slog.HandlerOptions{Level: logLeveler}

	var handler slog.Handler
	if *logFormat == "json" {
		handler = slog.NewJSONHandler(os.Stdout, handlerOpts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, handlerOpts)
	}

	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open log file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		if *logFormat == "json" {
			handler = slog.NewJSONHandler(f, handlerOpts)
		} else {
			handler = slog.NewTextHandler(f, handlerOpts)
		}
	}
	logger := slog.New(handler)

	logger.Info("config loaded", "listen", cfg.Listen)

	// -vvv 模式下额外打印默认后端地址
	if verbosity >= 3 {
		logger.Debug("config dump", "default_backend", cfg.DefaultBackend)
	}

	// ============================================================
	// 第四部分：可选的后台化(Daemonize)
	// "守护进程"就是在后台默默运行的程序,不和终端绑定。
	// 类似 Windows 的"服务"或 macOS 的后台进程。
	// ============================================================

	if *daemonize {
		fmt.Fprintf(os.Stderr, "Logging to %s\n", logPath)
		if err := daemon(); err != nil {
			logger.Error("daemonize failed", "error", err)
			os.Exit(1)
		}
		logger.Info("daemonized", "pid", os.Getpid())
	}

	// ============================================================
	// 第五部分：创建上下文 + 预热连接
	// context.WithCancel 让 PreWarm 和 AcceptLoop 能响应 shutdown 信号
	// ============================================================

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxy.PreWarm(ctx, cfg.Router(), 5*time.Second, logger) // 5秒超时

	// 创建原子路由器——SIGHUP 热加载时替换 router,新连接即时生效
	routerRef := proxy.NewRouterRef(cfg.Router())

	// ============================================================
	// 第六部分：开始监听网络连接
	// net.Listen 类似于"在门口挂上'营业中'的牌子",
	// 告诉操作系统："我在这里接收网络连接"。
	// ============================================================

	// 创建一个 TCP 监听器,在 cfg.Listen 指定的地址上等待连接
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		logger.Error("listen failed", "error", err)
		os.Exit(1)
	}
	defer ln.Close() // 程序退出时关闭监听器

	// ============================================================
	// 第七部分：信号处理(信号 = 操作系统发给程序的通知)
	// ============================================================

	// 要监听的信号列表：挂起(SIGHUP)、中断(SIGINT)、终止(SIGTERM)
	sigs := []os.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM}
	// 如果是 Linux,加上 SIGUSR1 用于切换日志级别
	if ts := toggleSignal; ts != nil {
		sigs = append(sigs, ts)
	}
	// 创建一个"信号通道",容量为1。操作系统会把收到的信号放进这个通道。
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, sigs...) // 开始监听

	// 启动一个后台 goroutine(Go 的轻量级"线程")专门处理信号
	go func() {
		// range 会在这个通道上循环等待,每次收到一个信号就处理
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				// SIGHUP：重新读取配置文件
				// Reload 尝试加载新配置,如果新文件有错,保留旧配置不变
				newCfg, err := config.Reload(*configPath, cfg)
				if err != nil {
					logger.Error("config reload failed, keeping old config", "error", err)
				} else {
					cfg = newCfg
					routerRef.Store(cfg.Router()) // 原子替换路由表,新连接即时生效
					logger.Info("config reloaded")
				}

			case syscall.SIGINT, syscall.SIGTERM:
				// SIGINT(用户按 Ctrl+C) 或 SIGTERM(系统要求退出)
				logger.Info("shutting down...")
				cancel()   // 通知所有工作 goroutine 停止
				ln.Close() // 关闭监听器，让 Accept() 立即返回
				return     // 退出信号处理循环

			default:
				// SIGUSR1：切换日志级别（Debug ↔ 原始级别）
				if sig == toggleSignal {
					newLevel := slog.LevelDebug
					if logLeveler.Level() == slog.LevelDebug {
						newLevel = level
					}
					logLeveler.Set(newLevel)
					logger.Info("log level toggled", "level", newLevel)
				}
			}
		}
	}()

	// ============================================================
	// 第八部分：启动代理主循环
	// AcceptLoop 是一个"无限循环",不断接收新连接并处理。
	// 只有 ctx 被取消(即收到关闭信号)时才会退出。
	// ============================================================

	logger.Info("proxy started", "listen", cfg.Listen)

	if cfg.DebugAddr != "" {
		go func() {
			logger.Info("pprof listener", "addr", cfg.DebugAddr)
			if err := http.ListenAndServe(cfg.DebugAddr, nil); err != nil {
				logger.Error("pprof server", "error", err)
			}
		}()
	}

	if err := proxy.AcceptLoop(ctx, ln, routerRef, cfg.MaxConnections, logger); err != nil {
		logger.Error("accept loop error", "error", err)
	}

	logger.Info("proxy stopped") // 到这里说明程序正常退出了
}
