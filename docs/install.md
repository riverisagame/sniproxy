# sniproxy 安装与使用指南

适用于 Debian 13 (amd64)，使用 systemd 管理服务。

## 1. 项目简介

sniproxy 是一个基于 TLS SNI（Server Name Indication）的反向代理。它监听一个端口（默认 443），读取 TLS ClientHello 中的 SNI 域名，根据配置将连接转发到对应的后端服务器。

## 2. 编译

在开发机上交叉编译 Linux amd64 二进制：

```bash
git clone https://github.com/riverisagame/sniproxy.git
cd sniproxy
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o sniproxy ./cmd/sniproxy/
```

参数说明：
- `GOOS=linux` — 目标系统 Linux
- `GOARCH=amd64` — 目标架构 amd64
- `CGO_ENABLED=0` — 禁用 CGO，生成纯静态二进制，无需 glibc
- `-ldflags="-s -w"` — 去除调试符号，减小体积

## 3. 安装

### 3.1 放置二进制

```bash
scp sniproxy root@<server>:/usr/local/bin/
ssh root@<server> chmod +x /usr/local/bin/sniproxy
```

验证：

```bash
/usr/local/bin/sniproxy -h
```

### 3.2 配置

```bash
mkdir -p /etc/sniproxy
```

编辑 `/etc/sniproxy/config.yaml`：

```yaml
listen: ":443"                           # 监听地址和端口
default_backend: "127.0.0.1:8443"        # 默认后端（无匹配时使用）
max_connections: 0                        # 最大并发连接数，0 表示不限制
log_level: "info"                         # debug | info | warn | error
log_file: ""                              # 日志文件路径，留空由 systemd journald 接管

routes:
  - sni:
      - "api.example.com"
      - "admin.example.com"
    backend: "10.0.0.1:443"
  - sni:
      - "*.example.com"
    backend: "10.0.0.2:8443"
```

配置项说明：

| 字段 | 类型 | 说明 |
|------|------|------|
| `listen` | string | 监听地址，如 `:443` 或 `0.0.0.0:443` |
| `default_backend` | string | 无匹配路由时的默认后端 |
| `max_connections` | int | 最大并发连接数，0 不限制 |
| `log_level` | string | `debug` / `info` / `warn` / `error` |
| `log_file` | string | 日志文件路径，systemd 下建议留空 |
| `routes` | array | 路由规则列表 |
| `routes[].sni` | array | SNI 域名列表，支持 `*` 通配符（如 `*.example.com`），匹配遵循最长前缀原则 |
| `routes[].backend` | string | 匹配时转发的后端地址 |

### 3.3 安装 systemd 服务

```bash
cp debian/sniproxy.service /etc/systemd/system/
systemctl daemon-reload
```

### 3.4 启用并启动

```bash
systemctl enable --now sniproxy
```

检查状态：

```bash
systemctl status sniproxy
```

## 4. 日常管理

### 4.1 服务控制

```bash
systemctl start sniproxy       # 启动
systemctl stop sniproxy        # 停止
systemctl restart sniproxy     # 重启（连接会中断）
systemctl reload sniproxy      # 热加载配置（发送 SIGHUP，连接不中断）
systemctl status sniproxy      # 查看状态
systemctl enable sniproxy      # 开机自启
systemctl disable sniproxy     # 禁用开机自启
```

### 4.2 查看日志

```bash
journalctl -u sniproxy -f                    # 实时跟踪（Ctrl+C 退出）
journalctl -u sniproxy --since "1 hour ago"  # 最近 1 小时
journalctl -u sniproxy --since today          # 今天的日志
journalctl -u sniproxy -n 100                 # 最近 100 行
```

### 4.3 配置文件热加载

修改配置文件后，无需重启：

```bash
vim /etc/sniproxy/config.yaml
systemctl reload sniproxy
```

如果新配置有语法错误，程序会保留旧配置不变，并在日志中输出错误信息。

### 4.4 切换日志级别

发送 SIGUSR1 信号可在 `debug` 和原始级别之间切换（无需重启）：

```bash
systemctl kill -s SIGUSR1 sniproxy
```

## 5. 防火墙

如果使用 iptables/nftables 且为白名单模式，需要放行监听端口：

```bash
# nftables 示例
nft add rule inet filter input tcp dport 443 accept
```

## 6. 监控与健康检查

检测进程是否存活：

```bash
systemctl is-active sniproxy
```

检测端口是否监听：

```bash
ss -tlnp | grep 443
```

## 7. 故障排查

### 启动失败

```bash
# 查看详细日志
journalctl -u sniproxy -n 50 --no-pager

# 手动启动排查（前台运行，加 -vv 看详细日志）
/usr/local/bin/sniproxy -c /etc/sniproxy/config.yaml -vv
```

### 常见错误

| 错误 | 原因 | 解决 |
|------|------|------|
| `listen failed: permission denied` | 非 root 绑定 443 失败 | 确认 service 文件包含 `AmbientCapabilities=CAP_NET_BIND_SERVICE` |
| `load config failed` | 配置文件不存在或格式错误 | 检查 `/etc/sniproxy/config.yaml` 路径和 YAML 语法 |
| `connect: connection refused` | 后端服务不可达 | 检查后端地址是否正确、后端服务是否启动 |

### 手动重新编译升级

```bash
# 1. 停止服务
systemctl stop sniproxy

# 2. 替换二进制
scp sniproxy root@<server>:/usr/local/bin/
ssh root@<server> chmod +x /usr/local/bin/sniproxy

# 3. 启动服务
systemctl start sniproxy
```

## 8. 卸载

```bash
systemctl stop sniproxy
systemctl disable sniproxy
rm /etc/systemd/system/sniproxy.service
rm /usr/local/bin/sniproxy
rm -rf /etc/sniproxy
systemctl daemon-reload
```
