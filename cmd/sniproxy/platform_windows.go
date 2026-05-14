//go:build windows
// 上面这行是 Go 的"构建标签"(build tag)。
// 它告诉 Go 编译器：这个文件只在 Windows 系统上编译。
// 在 Linux 或 Mac 上编译时,这个文件会被忽略。

package main

import (
	"os" // 操作系统接口,这里只用到了 os.Signal 类型
)

// extraSignals 返回 Windows 特有的信号。
// Windows 不像 Linux 那样有 SIGUSR1 这种信号机制,
// 所以直接返回 nil(空),表示"没有额外信号"。
func extraSignals() []os.Signal {
	return nil
}

// daemon 在 Windows 上的实现。
//
// 在 Linux 上,"守护进程"(后台服务)是通过 fork(分叉)进程实现的。
// 但 Windows 没有 fork 这个概念——Windows 的服务是通过 SCM(服务控制管理器)管理的。
//
// 所以这个函数在 Windows 上什么都不做,直接返回 nil。
// 这意味着 -d 参数在 Windows 上被"静默忽略"——程序会正常运行但不会后台化。
func daemon() error {
	return nil
}
