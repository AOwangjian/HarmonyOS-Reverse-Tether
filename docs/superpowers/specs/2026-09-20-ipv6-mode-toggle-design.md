# IPv6 代理模式开关 — 设计文档

日期：2026-09-20
状态：待实现

## 背景

relay 已具备 IPv6 真代理能力（RFC 8200 伪头校验和、双向回包链路），native
隧道也已放行 IPv6。但行为是写死的：IPv6 总是被代理，用户无法选择。

两个未覆盖的真实场景：

1. 用户只想用 IPv4，希望 IPv6 交回系统处理
2. 电脑没有 IPv6 出口（当前就是这种情况）时，IPv6 流量应当被明确拒绝，
   而不是发出去等超时——否则应用会以为 IPv6 可用，反复重试

## 目标

在主页提供三档 IPv6 行为选择，并让"拒绝"这一档真正快速生效。

## 非目标

- 不支持 IPv6 扩展头与分片包（relay 解析层已明确拒绝，本次不改）
- 不提供按应用分流的 IPv6 策略
- 不在电脑端提供对应开关（控制权在手机 UI）

## 状态模型

```typescript
export enum Ipv6Mode {
  Off = 0,        // 不接管：VPN 不下发 IPv6 路由，系统自行处理
  Proxy = 1,      // 真代理：IPv6 经电脑转发出网
  Blackhole = 2   // 黑洞：捕获 IPv6 并回 ICMPv6 unreachable
}
```

三档由两个 UI 开关表达：主开关决定 Off 与"接管"，子开关在接管内区分
Proxy 与 Blackhole。

### 为什么设置独立存储

`TetherState`（`tether-status.json`）由 VPN 进程周期性覆写运行时统计。
把用户设置放进去会被 `saveState` 冲掉。因此新增
`tether-settings.json`，与 `privacy-consent.json` 同级，沿用同样的
原子写（写 `.tmp` 后 `rename`）。

设置与运行时状态分离，各自独立演进，不存在覆写竞态。

## 配置传递链路

```
Index.ets (UI 进程)
   │  saveIpv6Mode() → tether-settings.json
   │  startVpn(want.parameters.ipv6Mode)
   ▼
TetherVpnAbility (VPN 进程)
   │  onCreate: 优先 want 参数，缺省回落设置文件
   │  ① 决定 VpnConfig 是否下发 IPv6 地址与路由
   │  ② tether.start(tunFd, socketFd, session, ipv6Mode)
   ▼
tunnel.cpp (native 线程)
      按模式决定 IPv6 包：转发 / 回 ICMPv6
```

双重来源是必要的：VPN 可能由 HDC 或系统重启拉起，那时没有 want 参数。
这与现有 `port` 的处理方式一致（`loadState(...).port ?? PORT`）。

### 各层职责

**VpnConfig（ArkTS）**

- `Off`：只下发 IPv4 地址与路由。不给 IPv6 路由，系统就不会把 IPv6
  交给隧道——这是 Off 语义的落点
- `Proxy` / `Blackhole`：额外下发 `fd00::2/128` 地址与 `::/0` 路由

**native（C++）**

- `Proxy`：IPv6 包校验通过则转发给 relay
- `Blackhole`：不转发，构造 ICMPv6 unreachable 写回 tun，并计入 `dropped_`
- `Off`：理论上收不到 IPv6（无路由），收到也丢弃

黑洞计入 `dropped_` 而非静默丢弃，使主页统计能反映黑洞正在工作。
这是可验证性要求，不是装饰。

## ICMPv6 Destination Unreachable

### 为什么不用静默丢弃

静默丢弃下，应用发出 SYN 收不到任何回应，只能等系统超时重试耗尽
（TCP 约 75 秒）。用户感受是"网页卡住"。回 ICMPv6 则让应用立刻得知
目标不可达，触发 Happy Eyeballs 回落 IPv4。

### 报文构造

```
IPv6 头（40B）  源/目的互换，next_header=58，hop_limit=64
ICMPv6 头（8B） type=1 (Destination Unreachable)
                code=1 (Communication with destination administratively
                        prohibited)
                checksum，unused=0
原包引用         截断至总长不超过 1280 字节
```

校验和按 RFC 4443 §2.3 覆盖 IPv6 伪头，算法与 `ipv6_packetizer.rs`
中已验证的实现相同，仅 next_header 取 58。

### 两处必须遵守的约束

**1. 总长不超过 1280 字节（RFC 4443 §3.1）**

引用的原包必须截断。超长报文会被部分协议栈丢弃。

**2. 不对错误报文或组播回应（RFC 4443 §2.4）**

收到 ICMPv6 错误报文、或目的地址为组播时，不得回 unreachable，
否则可能形成报文风暴。判断后直接丢弃。

实践中这条尤其重要：VPN 建链初期会有 MLD/邻居发现组播，当前日志
已观察到 4 个此类包。

### 测试策略

native 层没有测试框架（relay 有 cargo test，app 侧没有）。应对方式：

- 把校验和与报文构造写成纯函数，不依赖 tun/socket
- 在 relay 的 Rust 测试中用相同算法交叉验证校验和（接收方视角折叠
  应得 `0xffff`）
- 真机验证：黑洞档下 `dropped_` 计数增长，且应用回落 IPv4 的耗时
  显著短于 75 秒

这比 relay 侧的验证弱，是已知的取舍。

## UI

主页「连接/断开」下方新增设置卡片：

```
┌─────────────────────────────────┐
│  代理 IPv6                  [○] │
│  <随状态变化的副标题>             │
├─────────────────────────────────┤  ← 仅主开关开启时出现
│  黑洞模式                   [○] │
│  <随状态变化的副标题>             │
└─────────────────────────────────┘
```

层级通过缩进与分隔线表达；主开关关闭时子项整体隐藏（ArkTS 条件渲染），
不使用禁用态。

副标题随状态变化：

| 状态 | 副标题 |
|---|---|
| Off | 系统自行处理 IPv6，可能绕过隧道 |
| Proxy | IPv6 经电脑转发出网 |
| Blackhole | 拦截 IPv6 并拒绝，应用将回落 IPv4 |

Off 档明示"可能绕过隧道"是有意为之：这是真实的泄漏风险，不应隐藏。

控件使用鸿蒙原生 `Toggle({ type: ToggleType.Switch })`，配色沿用
`$r('sys.color.*')`，与现有风格一致。

### 切换时机

改动后若 VPN 正在运行，自动 `stop()` → `start()` 使其生效，期间状态栏
显示「正在应用新设置…」。网络中断约 1-2 秒。

不采用"仅下次连接生效"，因为用户改完看不到变化会困惑。

## 改动清单

| 文件 | 改动 |
|---|---|
| `common/Ipv6Settings.ets` | 新建：枚举与原子读写 |
| `pages/Index.ets` | 设置卡片与切换重连 |
| `vpn/TetherVpnAbility.ets` | 按模式决定 VpnConfig；向 native 传模式 |
| `cpp/tunnel.cpp` | 模式判定与 ICMPv6 构造 |
| `cpp/napi_init.cpp` | `start` 参数 3 → 4 |
| `common/HelpContent.ets` | 新增帮助条目说明三档 |

## 兼容性

`tether.start` 增加参数属破坏性变更，但 native 与 ArkTS 同包发布，
不存在版本错配。

设置文件缺失时默认 `Off`，与当前行为一致——老用户升级后网络行为
不会无预期改变。

## 验证结果（2026-09-20，设备 8BBUT26804003716）

三档在同一部设备上依次切换，唯一变量是界面开关：

| 档位 | 到达 relay 的 IPv6 包 | 同期 IPv4 业务 |
|---|---|---|
| Off | 0 | 正常 |
| Proxy | 6 | 正常 |
| Blackhole | 0（本地拒绝） | TCP 12、DNS 9，网页正常打开 |

Off 与 Proxy 的对比证明 `VpnConfig` 的路由控制生效：不下发 `::/0` 时
系统自行处理 IPv6，下发后包进入隧道并到达 relay。

Blackhole 与 Proxy 的对比证明拦截发生在手机本地：同样捕获 IPv6，但
relay 一个包也没收到，而 IPv4 业务不受影响。

实现期间修复了两个只在运行期暴露的缺陷：

1. `tether.start` 的 TypeScript 声明未同步，导致干净工作区编译失败；
   增量构建复用缓存声明因而掩盖了它。
2. `Args()` 硬编码三元素缓冲区，请求第四个参数时读越界，VPN 进程
   SIGSEGV。这类错误编译器不报，native 层又无单元测试——正是本文档
   "测试策略"一节预先标注的弱点。

## 已知限制

- 电脑当前无 IPv6 出口，`Proxy` 档的端到端能力仍无法验证。本设计
  不解决该环境问题
- ICMPv6 仅覆盖 Destination Unreachable，不实现 Packet Too Big 等
  其他类型
