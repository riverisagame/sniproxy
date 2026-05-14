//go:build linux
// 上面这行是 Go 的"构建标签"(build tag)。
// 它告诉 Go 编译器：这个文件只在 Linux 系统上编译。
// 在 Windows 或 Mac 上编译时,这个文件会被忽略。

package main

import (
	"os"      // 操作系统接口,这里用于 os.Executable()、os.Getppid()、os.Exit()
	"os/exec" // 执行外部命令,这里用于重新启动自己的进程
	"syscall" // 低层系统调用,这里用于 syscall.Setsid()
)

// init() 是一个特殊的函数,在 main() 之前自动执行。
// 它把 toggleSignal 设置为 SIGUSR1 —— Linux 上的"用户自定义信号1"。
// 这个信号用于在程序运行时切换日志的详细程度。
func init() {
	toggleSignal = syscall.SIGUSR1
}

// daemon 把当前程序变成"守护进程"(daemon)。
//
// 守护进程是什么？
// 想象你打开终端运行一个程序,关了终端程序就没了。
// 守护进程则不同——它脱离终端独立运行,就算你注销登录它也还在。
// 服务器软件(nginx、mysql 等)通常以守护进程方式运行。
//
// 这个函数分两步工作：
//   第1步（父进程）：重新启动一个和自己一模一样的子进程,然后父进程退出
//   第2步（子进程）：调用 Setsid() 让自己彻底脱离终端
//
// 为什么要重新启动而不是直接在原地变身？
// 因为"脱离终端"需要满足很多条件,最可靠的方式就是"重新来过"——
// 让 init 进程(PID=1)成为新进程的父进程。
func daemon() error {
	// os.Getppid() 获取"父进程ID"。
	// 如果父进程 ID 不是 1,说明我们还在用户启动的原始进程中,需要"分叉"。
	// 如果父进程 ID 已经是 1(init 进程),说明我们已经是子进程了,跳到后面。
	if os.Getppid() != 1 {
		// --- 父进程的逻辑 ---

		// 获取当前可执行文件的路径
		// 比如 /usr/local/bin/sniproxy
		exe, err := os.Executable()
		if err != nil {
			return err
		}

		// 启动一个新的进程,执行的是同一个程序文件
		// os.Args[1:] 把当前收到的命令行参数原样传过去
		// 比如 ./sniproxy -c config.yaml -d → 子进程也是 ./sniproxy -c config.yaml -d
		cmd := exec.Command(exe, os.Args[1:]...)

		// 关键：把 stdin/stdout/stderr 都设为 nil
		// 这样子进程就不再有终端关联了——它成了一个"孤儿"进程
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil

		// 启动子进程
		if err := cmd.Start(); err != nil {
			return err
		}

		// 父进程退出(退出码0 = 正常退出)
		// 此时子进程的父进程会变成 init 进程(PID=1)
		os.Exit(0)
	}

	// --- 子进程的逻辑 ---
	// 执行到这里说明父进程 ID == 1,我们是子进程

	// Setsid() 创建一个新的"会话"(session),让进程彻底脱离终端。
	// 这确保了即使你关闭了启动它的终端窗口,它也不会被杀死。
	_, err := syscall.Setsid()
	return err
}
