// package config 负责"读配置"这件事。
//
// 配置文件是一个 YAML 文件,长得像这样：
//
//   listen: ":443"
//   default_backend: "127.0.0.1:8443"
//   max_connections: 0              # 最大并发连接,0=不限制
//   log_level: "error"             # debug | info | warn | error
//   log_file: ""                   # 日志文件路径,空=仅 stdout
//   routes:
//     - sni:
//         - "api.example.com"
//         - "admin.example.com"
//       backend: "10.0.0.1:443"
//     - sni:
//         - "*.example.com"
//       backend: "10.0.0.2:8443"
//
// 这个包的 Load 函数把 YAML 文件读进来,然后构建一个"路由器"(Router),
// 路由器负责回答"这个域名应该转发到哪个后端服务器"。
package config

import (
	"fmt"   // 格式化错误消息
	"os"    // 读文件
	"slices" // 泛型 slice 工具

	"gopkg.in/yaml.v3" // 第三方库,用于解析 YAML 格式

	"sniproxy/internal/router" // 我们的路由器模块
)

// Config 是"配置"的 Go 语言表示。
// 每个字段后面的 `yaml:"xxx"` 是"结构体标签"(struct tag),
// 告诉 YAML 解析器：YAML 文件里的 xxx 字段对应到这个 Go 字段。
//
// 字段说明：
//   Listen         - 代理监听哪个地址和端口,比如 ":443"(所有网卡的443端口)
//   DefaultBackend - 兜底后端。如果域名匹配不到任何规则,就转发到这里
//   Routes         - 路由规则列表,每条规则包含一组 SNI 域名和一个目标后端
//   r              - 小写开头=私有字段。根据 Routes 构建的路由器,不直接暴露
type Config struct {
	Listen         string  `yaml:"listen"`          // 监听地址,默认 ":443"
	DefaultBackend string  `yaml:"default_backend"` // 默认后端,可选
	MaxConnections int     `yaml:"max_connections"` // 最大并发连接,0=不限制
	Routes         []Route `yaml:"routes"`          // 路由规则数组
	LogLevel       string  `yaml:"log_level"`       // 日志级别: debug/info/warn/error,默认 "error"
	LogFile        string  `yaml:"log_file"`        // 日志文件路径,默认空(仅 stdout)
	DebugAddr      string  `yaml:"debug_addr"`      // pprof 监听地址,空=禁用

	r *router.Router // 内部路由器(不导出,用 Router() 方法访问)
}

// Route 是一条"域名 → 后端"的转发规则。
//
// 例如配置：
//   sni: ["api.example.com", "admin.example.com"]
//   backend: "10.0.0.1:443"
//
// 表示：访问 api.example.com 或 admin.example.com 时,转发到 10.0.0.1:443
type Route struct {
	SNI     []string `yaml:"sni"`     // 一组 SNI 域名,可以有多个
	Backend string   `yaml:"backend"` // 这些域名对应的后端服务器地址
}

// Load 从 YAML 文件加载配置,返回一个构建好的 Config 对象。
//
// 参数 path：YAML 文件的路径
// 返回值：
//   *Config — 配置对象指针
//   error   — 如果文件不存在或格式不对,返回错误
func Load(path string) (*Config, error) {
	// 第一步：读取整个文件到内存
	data, err := os.ReadFile(path)
	if err != nil {
		// %w 是 Go 1.13+ 的"错误包装",保留原始错误信息
		return nil, fmt.Errorf("read config: %w", err)
	}

	// 第二步：把 YAML 文本解析成 Config 结构体
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// 第三步：设置默认值
	// 如果用户没写 listen 字段,就用 ":443" (HTTPS 标准端口)
	if cfg.Listen == "" {
		cfg.Listen = ":443"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "error"
	}

	// 验证日志级别合法值
	validLevels := []string{"debug", "info", "warn", "error"}
	if !slices.Contains(validLevels, cfg.LogLevel) {
		return nil, fmt.Errorf("invalid log_level %q: must be one of %v", cfg.LogLevel, validLevels)
	}

	// 第四步：根据路由规则构建路由器
	// default_backend 可选——不填则无匹配的 SNI 直接静默丢弃
	// buildRouter 把配置里的 []Route 转换成路由器能快速查的表
	cfg.r = buildRouter(cfg.Routes, cfg.DefaultBackend)

	return cfg, nil
}

// buildRouter 把 YAML 中的路由规则转换成 Router 对象。
//
// YAML 中的路由是按"后端地址"分组的,每个后端对应一组 SNI 域名。
// 但 Router 需要的是按"域名→后端"的映射,所以这里做一个格式转换。
//
// 参数：
//   routes         - YAML 中解析出的路由规则列表
//   defaultBackend - 默认后端地址
func buildRouter(routes []Route, defaultBackend string) *router.Router {
	// 创建一个 map,key 是后端地址,value 是属于这个后端的 SNI 域名列表
	m := make(map[string][]string, len(routes))
	for _, rt := range routes {
		// append 把 rt.SNI 里的所有域名追加到 m[rt.Backend] 的列表中
		// 如果 m[rt.Backend] 还不存在,Go 会自动创建一个空的切片
		m[rt.Backend] = append(m[rt.Backend], rt.SNI...)
	}
	// 调用路由器构造函数,内部会区分"精确匹配"和"通配符匹配"
	return router.New(m, defaultBackend)
}

// Reload 重新读取配置文件,用于"热更新"——不停机就更新路由规则。
//
// 一个巧妙的设计：
// 如果新配置文件有语法错误,会返回旧配置 + 错误信息。
// 这样即使管理员写错了配置文件,代理也不会"崩掉",
// 而是继续用旧规则运行,等管理员修好文件后再发 SIGHUP 重试。
//
// 参数：
//   path - 配置文件路径
//   cfg  - 当前正在使用的配置(作为"回退"选项)
func Reload(path string, cfg *Config) (*Config, error) {
	newCfg, err := Load(path)
	if err != nil {
		// 新配置加载失败？返回旧配置 + 错误,不影响运行中的服务
		return cfg, err
	}
	return newCfg, nil
}

// Router 返回配置中内置的路由器。
// 代理需要用路由器来做"SNI 域名 → 后端地址"的查询。
func (c *Config) Router() *router.Router { return c.r }
