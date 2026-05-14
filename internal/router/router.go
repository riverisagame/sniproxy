// package router 实现了一个"域名路由器"。
//
// 它的工作很简单——就像快递分拣中心：
//   1. 看到包裹(连接)上写的地址(SNI域名)
//   2. 查表找到对应的卡车(后端服务器)
//   3. 把包裹送上去
//
// 这个路由器支持三种匹配方式,用生活中寄快递来类比：
//   - 精确匹配：写明了"北京市朝阳区XX路XX号" → 直接送到
//   - 通配符匹配：写了"北京市朝阳区*" → 匹配朝阳区的所有地址
//   - 默认兜底：地址看不清楚 → 送到一个默认的集散中心
//
// 在程序里：
//   - 精确匹配：api.example.com → 10.0.0.1:443
//   - 通配符匹配：*.example.com → 10.0.0.2:8443(匹配 www.example.com、mail.example.com 等)
//   - 默认兜底：匹配不上任何规则 → 发送到 default_backend
//
// 性能特点：O(1) 时间复杂度。
// 也就是不管你配置了多少条规则(100条还是10000条),
// 每次查询都只需要1~2次 hash map 查找,速度几乎一样快。
// 这就像字典查词——不管字典有多厚,翻到某个词的时间差不多(如果你按字母直接定位)。
package router

import "strings" // 字符串操作,这里用于查找 "." 和处理 "*." 前缀

// Router 的核心数据结构。
// 用两个 hash map + 一个默认值实现 O(1) 查找。
//
// hash map(也叫字典、映射)是计算机里最快的查找结构之一。
// 你可以把它想象成一本"索引"——通过 key 直接翻到那一页,不需要从头翻到尾。
//
// 字段说明：
//   exact    - 精确匹配表。key="api.example.com" → value="10.0.0.1:443"
//   wildcard - 通配符表。  key="example.com"     → value="10.0.0.2:8443"
//              (注意：存的是去掉 "*." 之后的部分)
//   def      - 默认后端。当上面两个表都查不到时,就返回这个
type Router struct {
	exact    map[string]string // 精确域名 → 后端地址
	wildcard map[string]string // 通配符域名(去掉*.) → 后端地址
	def      string            // 兜底后端地址
}

// New 创建一个新的路由器。
//
// 参数 routes：
//   map 的 key 是后端地址,value 是属于这个后端的 SNI 域名列表。
//   这种"按后端分组"的格式和 YAML 配置结构一致,方便直接从配置构造。
//
// 例子：
//   routes = map[string][]string{
//       "10.0.0.1:443":  {"api.example.com", "admin.example.com"},
//       "10.0.0.2:8443": {"*.example.com"},
//   }
//   defaultBackend = "10.0.0.3:8443"
//
// 构造过程：
//   遍历每个后端和它的域名列表,
//   如果域名以 "*." 开头 → 去掉 "*." 前缀,存入 wildcard 表
//   否则 → 直接存入 exact 表
func New(routes map[string][]string, defaultBackend string) *Router {
	// 初始化 Router,预分配 map 容量(提高性能,减少内存分配)
	r := &Router{
		exact:    make(map[string]string),
		wildcard: make(map[string]string),
		def:      defaultBackend,
	}

	// 遍历每个后端和它的域名列表
	for backend, patterns := range routes {
		for _, p := range patterns {
			if strings.HasPrefix(p, "*.") {
				// 通配符域名,比如 "*.example.com"
				// p[2:] 去掉开头的两个字符 "*." 得到 "example.com"
				// 存入 wildcard 表
				domain := p[2:]
				r.wildcard[domain] = backend
			} else {
				// 精确域名,比如 "api.example.com"
				// 直接存入 exact 表
				r.exact[p] = backend
			}
		}
	}
	return r
}

// Lookup 根据 SNI 域名查找对应的后端地址。
//
// 查找顺序(优先级从高到低)：
//   1. 先查 exact 表——精确匹配优先
//   2. 再查 wildcard 表——把域名去掉最左标签后查
//   3. 都没有 → 返回默认后端
//
// 通配符匹配的细节：
//   假设请求的 SNI 是 "www.example.com"
//   1. 先在 exact 表里查 "www.example.com" → 没找到
//   2. 找到第一个 "." 的位置,取后面的部分 → "example.com"
//   3. 在 wildcard 表里查 "example.com" → 找到了！返回对应后端
//
//   假设请求的 SNI 是 "api.staging.example.com"
//   1. exact 表里没有
//   2. 去头得到 "staging.example.com" → wildcard 表里也没有(*.example.com 只匹配一级子域名)
//   3. 返回默认后端
//
// 时间复杂度：O(1)——最多两次 map 查找
func (r *Router) Lookup(sni string) string {
	// 第一步：精确匹配
	// map 的 comma-ok 模式：b 是值,ok 表示 key 是否存在
	if b, ok := r.exact[sni]; ok {
		return b
	}

	// 第二步：通配符匹配
	// strings.IndexByte 查找第一个 '.' 的位置
	// 比如 "www.example.com" → idx=3
	if idx := strings.IndexByte(sni, '.'); idx != -1 {
		// 取 '.' 后面的部分
		// "www.example.com"[4:] = "example.com"
		domain := sni[idx+1:]
		if b, ok := r.wildcard[domain]; ok {
			return b
		}
	}

	// 第三步：都没匹配到,返回默认后端
	return r.def
}

// UniqueBackends 返回所有"不重复"的后端地址。
// 主要用于 PreWarm(预热连接)——启动时挨个连接一遍所有后端服务器。
//
// 为什么要去重？
// 同一个后端地址可能出现在多个路由规则中,预热时只需要连一次就够了。
func (r *Router) UniqueBackends() []string {
	// 用 map 来去重。Go 没有 Set 类型,所以用 map[string]bool 模拟
	seen := make(map[string]bool)

	// 先把默认后端加进去（如果配置了的话）
	if r.def != "" {
		seen[r.def] = true
	}

	// 遍历 exact 表,收集所有后端地址
	for _, b := range r.exact {
		seen[b] = true
	}

	// 遍历 wildcard 表,收集所有后端地址
	for _, b := range r.wildcard {
		seen[b] = true
	}

	// 把 map 的 key 收集到切片中
	out := make([]string, 0, len(seen))
	for b := range seen {
		out = append(out, b)
	}
	return out
}
