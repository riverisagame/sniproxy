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
// 这是 ParseBytes 的便捷包装,返回 string 类型。
func Parse(data []byte) (string, error) {
	b, err := ParseBytes(data)
	if err != nil {
		return "", err
	}
	if b == nil {
		return "", nil
	}
	return string(b), nil
}

// ParseBytes 从一段 TLS ClientHello 数据中提取 SNI 主机名,返回原始字节切片。
// 返回的 []byte 是 data 的子切片,零分配。
//
// 参数 data：
//   一段原始字节数据,必须从 TLS 记录头开始(包含 content type、版本、长度)。
//
// 返回值：
//   []byte — 提取到的域名字节
//            如果客户端没有发送 SNI 扩展,返回 nil
//   error  — 如果数据格式不对,返回错误
func ParseBytes(data []byte) ([]byte, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("record too short: %d bytes", len(data))
	}

	contentType := data[0]
	if contentType != 0x16 {
		return nil, fmt.Errorf("not a TLS handshake record: type 0x%02x", contentType)
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))

	if len(data) < 5+recordLen {
		return nil, fmt.Errorf("truncated record: have %d, want %d", len(data), 5+recordLen)
	}

	payload := data[5 : 5+recordLen]

	if len(payload) < 4 {
		return nil, fmt.Errorf("handshake payload too short: %d", len(payload))
	}

	msgType := payload[0]
	if msgType != 0x01 {
		return nil, fmt.Errorf("not a ClientHello: msg_type %d", msgType)
	}

	return parseClientHelloBody(payload[4:])
}

// parseClientHelloBody 解析 ClientHello 消息的主体部分。
func parseClientHelloBody(body []byte) ([]byte, error) {
	pos := 0

	if len(body) < pos+2 {
		return nil, fmt.Errorf("truncated at version")
	}
	pos += 2

	if len(body) < pos+32 {
		return nil, fmt.Errorf("truncated at random")
	}
	pos += 32

	if len(body) < pos+1 {
		return nil, fmt.Errorf("truncated at session_id length")
	}
	sidLen := int(body[pos])
	pos += 1 + sidLen
	if len(body) < pos {
		return nil, fmt.Errorf("truncated at session_id")
	}

	if len(body) < pos+2 {
		return nil, fmt.Errorf("truncated at cipher_suites length")
	}
	csLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2 + csLen
	if len(body) < pos {
		return nil, fmt.Errorf("truncated at cipher_suites")
	}

	if len(body) < pos+1 {
		return nil, fmt.Errorf("truncated at compression length")
	}
	cmLen := int(body[pos])
	pos += 1 + cmLen
	if len(body) < pos {
		return nil, fmt.Errorf("truncated at compression_methods")
	}

	if pos == len(body) {
		return nil, nil
	}

	if len(body) < pos+2 {
		return nil, fmt.Errorf("truncated at extensions length")
	}
	extLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	extEnd := pos + extLen
	if len(body) < extEnd {
		return nil, fmt.Errorf("truncated in extensions")
	}

	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[pos:])
		extDataLen := int(binary.BigEndian.Uint16(body[pos+2:]))
		pos += 4

		if pos+extDataLen > extEnd {
			return nil, fmt.Errorf("extension data overflows")
		}

		if extType == sniExtensionType {
			return parseSNIExtension(body[pos : pos+extDataLen])
		}

		pos += extDataLen
	}

	return nil, nil
}

// parseSNIExtension 从 SNI 扩展数据中提取主机名。
func parseSNIExtension(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("SNI extension too short")
	}

	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	end := 2 + listLen
	if len(data) < end {
		end = len(data)
	}
	data = data[2:end]

	pos := 0
	for pos+3 <= len(data) {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1:]))
		pos += 3

		if pos+nameLen > len(data) {
			return nil, fmt.Errorf("SNI name overflows")
		}

		if nameType == 0x00 {
			return data[pos : pos+nameLen], nil
		}

		pos += nameLen
	}

	return nil, nil
}
