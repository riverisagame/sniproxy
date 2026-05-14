// Package sni 实现了从 TLS 握手中提取 SNI 域名的功能。
//
// 先了解几个概念,方便理解后面的代码：
//
// === 什么是 TLS？ ===
// TLS(Transport Layer Security,传输层安全)是互联网加密通信的基础。
// 你访问 HTTPS 网站时,浏览器和服务器之间会建立一个 TLS 加密通道,
// 类似于两人之间拉了一条别人看不到的加密电话线。
// TLS 的前身叫 SSL,所以有时候你也会看到 SSL/TLS 这种说法。
//
// === 什么是 SNI？ ===
// SNI(Server Name Indication,服务器名称指示)是 TLS 协议的一个扩展。
//
// 它解决什么问题？
// 一个服务器(同一个 IP)上可能托管了多个网站(比如 example.com 和 example.org)。
// 在 TLS 握手的"打招呼"阶段,客户端(浏览器)需要告诉服务器:
// "我想访问的是 example.com,请给我这个网站的证书"。
// 这样服务器才知道用哪个证书来加密。
//
// 就像你去一栋大楼,门禁问你去哪家公司,你说"去12楼A公司",
// 门禁才能给你正确的通行证——SNI 就是你说出的那个"公司名"。
//
// === 什么是 ClientHello？ ===
// ClientHello 是 TLS 握手的第一步,由客户端发送。
// 它是客户端对服务器说的"第一句话",内容包含：
//   - 支持的 TLS 版本
//   - 支持的加密算法列表
//   - 一个随机数
//   - 以及各种扩展(包括 SNI)
//
// 这个包的工作：截获 ClientHello 消息,从中提取出 SNI 域名,
// 然后根据域名决定把请求转发到哪个后端服务器。
//
// 支持 TLS 1.0 到 1.3,遵循 RFC 6066 第3节标准。
package sni

import (
	"encoding/binary" // 用于解析网络字节序(大端序)的整数
	"fmt"             // 格式化错误消息
)

// sniExtensionType 是 SNI 扩展在 TLS 协议中的"类型编号"。
// TLS 扩展有很多种,每种有一个唯一编号,
// SNI 的编号是 0x0000(十六进制,等于十进制的 0)。
const (
	sniExtensionType = 0x0000 // 这就像"学生证"上的编号——0号代表SNI扩展
)

// Parse 从一段 TLS ClientHello 数据中提取 SNI 主机名。
//
// 参数 data：
//   一段原始字节数据,必须从 TLS 记录头开始(包含 content type、版本、长度)。
//   通常是从网络连接中读到的第一段数据。
//
// 返回值：
//   string — 提取到的域名(比如 "api.example.com")
//           如果客户端没有发送 SNI 扩展,返回空字符串 ""
//   error  — 如果数据格式不对(不是 TLS、数据不完整等),返回错误
//
// 这个函数的工作流程：
//   1. 检查 TLS 记录头(5字节)：确认是 Handshake 类型
//   2. 读取记录体
//   3. 在记录体中解析 ClientHello 消息
//   4. 在 ClientHello 的扩展列表中找 SNI 扩展(编号 0x0000)
//   5. 从 SNI 扩展中提取域名
func Parse(data []byte) (string, error) {
	// ============================================================
	// 第一步：检查 TLS 记录头(Record Header)
	//
	// 每个 TLS 记录都以一个 5 字节的头开始：
	//   [0]    ContentType(1字节) — 这条记录的类型
	//   [1:3]  Version(2字节)     — TLS 版本
	//   [3:5]  Length(2字节)      — 后面跟着的数据有多长
	//
	// 图示(每个数字是一个字节)：
	//   +----+----+----+----+----+
	//   |0x16| Ver| Ver| Len| Len|
	//   +----+----+----+----+----+
	//   类型   版本         长度
	// ============================================================

	if len(data) < 5 {
		return "", fmt.Errorf("record too short: %d bytes", len(data))
	}

	// data[0] 是 ContentType
	// 0x16 = 22(十进制) = "Handshake"(握手消息)
	// 如果是 0x17 = Application Data,说明不是握手,是加密数据
	contentType := data[0]
	if contentType != 0x16 {
		return "", fmt.Errorf("not a TLS handshake record: type 0x%02x", contentType)
	}

	// 读取记录长度
	// binary.BigEndian.Uint16 从2个字节中解析出一个"大端序"的16位整数
	// 注意：data[3:5] = data[3]和data[4],是记录长度的两个字节
	// 网络协议通常用"大端序"(高位字节在前)
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))

	// 验证数据是否完整：实际数据长度 应该 ≥ 5(头) + recordLen(体)
	if len(data) < 5+recordLen {
		return "", fmt.Errorf("truncated record: have %d, want %d", len(data), 5+recordLen)
	}

	// ============================================================
	// 第二步：解析 Handshake 消息头
	//
	// Record Body 的前几个字节是 Handshake 协议的消息头：
	//   [0]    MsgType(1字节) — 握手消息类型
	//   [1:4]  Length(3字节)  — 消息体长度
	//
	// MsgType = 0x01 表示 ClientHello
	// 其他类型：
	//   0x02 = ServerHello
	//   0x0B = Certificate
	//   0x0F = CertificateVerify
	//   ... 等等
	// ============================================================

	// 取记录体(去掉5字节头)
	payload := data[5 : 5+recordLen]

	if len(payload) < 4 {
		return "", fmt.Errorf("handshake payload too short: %d", len(payload))
	}

	msgType := payload[0]
	if msgType != 0x01 { // 0x01 = ClientHello
		return "", fmt.Errorf("not a ClientHello: msg_type %d", msgType)
	}

	// 跳过 Handshake 消息头的3字节 length 字段
	// payload[1:4] 是长度,p[4:] 才是 ClientHello 的主体
	return parseClientHelloBody(payload[4:])
}

// parseClientHelloBody 解析 ClientHello 消息的主体部分。
//
// ClientHello 的结构(简化)：
//
//   struct {
//       uint16 client_version;        // 客户端支持的最高 TLS 版本
//       uint8  random[32];            // 32字节随机数
//       uint8  session_id<0..32>;     // 会话ID(可变长度,1字节长度前缀)
//       uint16 cipher_suites<2..>;    // 加密套件列表(2字节长度前缀)
//       uint8  compression_methods;   // 压缩方法列表(1字节长度前缀)
//       Extension extensions<0..>;    // 扩展列表(2字节长度前缀)——SNI在这里面！
//   } ClientHello;
//
//  "<0..32>" 表示是一个可变长度字段,前面有一个字节表示长度
//  "<2..>" 表示前面有两个字节表示长度
//
// 这些"长度前缀"很重要——因为每个字段长度不固定,必须知道每个字段多长,
// 才能算出下一个字段从哪开始。
func parseClientHelloBody(body []byte) (string, error) {
	// pos 是"当前读取位置",像指针一样告诉我们现在读到哪了
	pos := 0

	// ---- client_version：2字节 ----
	// 比如 0x03 0x03 表示 TLS 1.2
	//      0x03 0x04 表示 TLS 1.3
	if len(body) < pos+2 {
		return "", fmt.Errorf("truncated at version")
	}
	pos += 2 // 跳过,我们不需要版本号

	// ---- random：32字节 ----
	// 客户端生成的随机数,用于后续的加密密钥计算
	if len(body) < pos+32 {
		return "", fmt.Errorf("truncated at random")
	}
	pos += 32 // 跳过

	// ---- session_id：可变长度(1字节长度前缀 + N字节数据) ----
	// 用于"会话恢复"——如果客户端之前连接过,可以用旧的会话ID直接恢复加密通道
	if len(body) < pos+1 {
		return "", fmt.Errorf("truncated at session_id length")
	}
	sidLen := int(body[pos]) // 第一个字节是长度
	pos += 1 + sidLen        // 跳过长度字节 + 实际数据
	if len(body) < pos {
		return "", fmt.Errorf("truncated at session_id")
	}

	// ---- cipher_suites：可变长度(2字节长度前缀 + N字节数据) ----
	// 客户端支持的加密算法列表,比如 AES-GCM、ChaCha20-Poly1305
	if len(body) < pos+2 {
		return "", fmt.Errorf("truncated at cipher_suites length")
	}
	csLen := int(binary.BigEndian.Uint16(body[pos:])) // 长度是两个字节
	pos += 2 + csLen                                    // 跳过长度前缀 + 密码套件数据
	if len(body) < pos {
		return "", fmt.Errorf("truncated at cipher_suites")
	}

	// ---- compression_methods：可变长度(1字节长度前缀 + N字节数据) ----
	// 压缩方法列表,现代 TLS 通常只有一个值：0x00(不压缩)
	if len(body) < pos+1 {
		return "", fmt.Errorf("truncated at compression length")
	}
	cmLen := int(body[pos])
	pos += 1 + cmLen
	if len(body) < pos {
		return "", fmt.Errorf("truncated at compression_methods")
	}

	// ---- extensions：扩展列表(到这里了！) ----
	// 如果 pos 刚好等于 body 的长度,说明没有扩展部分
	if pos == len(body) {
		return "", nil // 没有扩展,返回空(无 SNI)
	}

	// 扩展部分的前2字节是总长度
	if len(body) < pos+2 {
		return "", fmt.Errorf("truncated at extensions length")
	}
	extLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	extEnd := pos + extLen // 扩展区域的结束位置
	if len(body) < extEnd {
		return "", fmt.Errorf("truncated in extensions")
	}

	// ---- 遍历每个扩展,找 SNI(类型=0x0000) ----
	// 每个扩展的结构：
	//   [0:2]  ExtensionType(2字节) — 扩展类型
	//   [2:4]  ExtensionLength(2字节) — 扩展数据长度
	//   [4:4+N] ExtensionData — 扩展数据
	for pos+4 <= extEnd { // 至少还需要4字节(type+length)
		extType := binary.BigEndian.Uint16(body[pos:])     // 扩展类型
		extDataLen := int(binary.BigEndian.Uint16(body[pos+2:])) // 扩展数据长度
		pos += 4 // 跳过 type 和 length

		// 安全检查：扩展数据不能超出边界
		if pos+extDataLen > extEnd {
			return "", fmt.Errorf("extension data overflows")
		}

		// 找到了！类型 0x0000 就是 SNI 扩展
		if extType == sniExtensionType {
			return parseSNIExtension(body[pos : pos+extDataLen])
		}

		// 不是 SNI,跳过这个扩展
		pos += extDataLen
	}

	// 遍历完所有扩展都没找到 SNI
	return "", nil
}

// parseSNIExtension 从 SNI 扩展数据中提取主机名。
//
// SNI 扩展的结构(在 RFC 6066 中定义)：
//
//   struct {
//       ServerName server_name_list<2..>;  // 服务器名称列表,2字节长度前缀
//   } ServerNameList;
//
//   每个 ServerName：
//       NameType name_type;    // 名称类型(1字节),0x00 = hostname(主机名)
//       uint16   name_length;  // 名称长度(2字节)
//       opaque   name<name_length>; // 实际的名称数据
//
// name_type 可以是：
//   0x00 = host_name(我们关心的域名)
//   0x01 = 其他类型(很少用)
func parseSNIExtension(data []byte) (string, error) {
	// 至少需要2字节的长度前缀
	if len(data) < 2 {
		return "", fmt.Errorf("SNI extension too short")
	}

	// 第一层：ServerNameList 的列表长度
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	end := 2 + listLen
	if len(data) < end {
		end = len(data) // 如果数据比声明的短,以实际为准
	}
	data = data[2:end] // 去掉外层长度前缀,得到实际的 ServerName 列表

	// 第二层：遍历每个 ServerName 条目
	pos := 0
	for pos+3 <= len(data) { // 至少需要 nameType(1) + nameLen(2) = 3字节
		nameType := data[pos]                                     // 名称类型(1字节)
		nameLen := int(binary.BigEndian.Uint16(data[pos+1:]))     // 名称长度(2字节)
		pos += 3 // 跳过 nameType 和 nameLen

		// 安全检查：名称数据不能超出边界
		if pos+nameLen > len(data) {
			return "", fmt.Errorf("SNI name overflows")
		}

		// nameType == 0x00 表示这个名称是主机名(域名),这正是我们需要的
		if nameType == 0x00 {
			// 把字节切片转为字符串并返回
			return string(data[pos : pos+nameLen]), nil
		}

		// 不是主机名类型,跳过
		pos += nameLen
	}

	// 遍历完没找到 host_name
	return "", nil
}
