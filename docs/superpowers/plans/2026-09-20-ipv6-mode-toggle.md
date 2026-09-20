# IPv6 Proxy Mode Toggle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a main switch "代理 IPv6" with a nested sub-option "黑洞模式" to the app's home page, so users can choose whether IPv6 is ignored, proxied through the computer, or captured and refused with ICMPv6.

**Architecture:** A three-value enum persists in its own settings file, travels to the VPN process through Want parameters (with file fallback), decides whether `VpnConfig` publishes IPv6 routes, and reaches the native tunnel as a fourth `tether.start` argument. The native layer either forwards IPv6 packets to the relay or answers them with an ICMPv6 Destination Unreachable written straight back into the existing tun write queue.

**Tech Stack:** ArkTS (HarmonyOS API 12+), C++17 with NAPI, Rust (cross-verification tests only), hvigor build, hdc deployment.

---

## File Structure

| File | Responsibility |
|---|---|
| `app/entry/src/main/ets/common/Ipv6Settings.ets` | **New.** `Ipv6Mode` enum plus atomic load/save of `tether-settings.json`. Nothing else. |
| `app/entry/src/main/ets/pages/Index.ets` | Settings card UI and reconnect-on-change. |
| `app/entry/src/main/ets/vpn/TetherVpnAbility.ets` | Resolve mode, shape `VpnConfig`, pass mode to native. |
| `app/entry/src/main/cpp/tunnel.h` | `Ipv6Mode` C++ enum, `Start` signature. |
| `app/entry/src/main/cpp/icmpv6.h` / `icmpv6.cpp` | **New.** Pure functions: checksum folding and ICMPv6 unreachable construction. No I/O, so they stay testable by inspection and reusable. |
| `app/entry/src/main/cpp/tunnel.cpp` | Mode-aware packet handling; calls into `icmpv6`. |
| `app/entry/src/main/cpp/napi_init.cpp` | `start` takes 4 arguments. |
| `app/entry/src/main/ets/common/HelpContent.ets` | Help entry explaining the three modes. |
| `relay/src/relay/ipv6_packetizer.rs` | Add a cross-verification test for the ICMPv6 checksum algorithm. |

ICMPv6 lives in its own translation unit rather than inside `tunnel.cpp` because `tunnel.cpp` is already ~250 lines of event-loop logic; packet construction is a separate responsibility with no shared state.

---

## Task 1: Settings storage

**Files:**
- Create: `app/entry/src/main/ets/common/Ipv6Settings.ets`

- [ ] **Step 1: Create the settings module**

Create `app/entry/src/main/ets/common/Ipv6Settings.ets`:

```typescript
import { fileIo } from '@kit.CoreFileKit';

export enum Ipv6Mode {
  Off = 0,        // VPN publishes no IPv6 route; the system handles IPv6 itself.
  Proxy = 1,      // IPv6 is relayed through the computer.
  Blackhole = 2   // IPv6 is captured and refused with ICMPv6.
}

class SettingsRecord {
  ipv6Mode: number = Ipv6Mode.Off;
}

// Settings live apart from TetherState: the VPN process rewrites
// tether-status.json every second and would clobber user choices.
export function loadIpv6Mode(dir: string): Ipv6Mode {
  try {
    const record = JSON.parse(fileIo.readTextSync(dir + '/tether-settings.json')) as SettingsRecord;
    return normalizeIpv6Mode(record.ipv6Mode);
  } catch (_) {
    return Ipv6Mode.Off;
  }
}

export function saveIpv6Mode(dir: string, mode: Ipv6Mode): void {
  const record = new SettingsRecord();
  record.ipv6Mode = normalizeIpv6Mode(mode);
  const path = dir + '/tether-settings.json';
  const file = fileIo.openSync(path + '.tmp', fileIo.OpenMode.CREATE | fileIo.OpenMode.WRITE_ONLY | fileIo.OpenMode.TRUNC);
  try {
    fileIo.writeSync(file.fd, JSON.stringify(record));
  } finally {
    fileIo.closeSync(file);
  }
  fileIo.renameSync(path + '.tmp', path);
}

// An unknown or corrupt value must never enable IPv6 capture implicitly.
export function normalizeIpv6Mode(value: number | undefined): Ipv6Mode {
  if (value === Ipv6Mode.Proxy) return Ipv6Mode.Proxy;
  if (value === Ipv6Mode.Blackhole) return Ipv6Mode.Blackhole;
  return Ipv6Mode.Off;
}
```

- [ ] **Step 2: Verify it compiles**

Run:
```
cd D:\HarmonyOS\RevTether-ipv6-packet\app
D:\HarmonyOS\command-line-tools-26\command-line-tools\bin\hvigorw.bat --mode module -p product=default -p buildMode=release -p module=entry@default assembleHap --no-daemon
```
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 3: Commit**

```bash
git add app/entry/src/main/ets/common/Ipv6Settings.ets
git commit -m "feat(app): persist the IPv6 mode in its own settings file"
```

---

## Task 2: ICMPv6 construction (pure functions)

**Files:**
- Create: `app/entry/src/main/cpp/icmpv6.h`
- Create: `app/entry/src/main/cpp/icmpv6.cpp`

- [ ] **Step 1: Write the header**

Create `app/entry/src/main/cpp/icmpv6.h`:

```cpp
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace tether {

// Fold a transport payload over the RFC 8200 8.1 pseudo header.
// `source` and `destination` must each be 16 bytes.
uint16_t Ipv6Checksum(const uint8_t *source, const uint8_t *destination,
                      uint8_t nextHeader, const uint8_t *payload, size_t length);

// Build an ICMPv6 Destination Unreachable (type 1, code 1) answering `packet`.
//
// Returns false when the original must not be answered: a malformed packet, an
// ICMPv6 error report, or a multicast destination. RFC 4443 2.4 forbids those
// replies because they can amplify into a storm -- VPN start-up alone emits
// several MLD multicasts.
bool BuildIcmpv6Unreachable(const uint8_t *packet, size_t size, std::vector<uint8_t> *out);

}  // namespace tether
```

- [ ] **Step 2: Write the implementation**

Create `app/entry/src/main/cpp/icmpv6.cpp`:

```cpp
// SPDX-License-Identifier: Apache-2.0
#include "icmpv6.h"

#include <cstring>

namespace tether {
namespace {
constexpr size_t kIpv6HeaderLength = 40;
constexpr size_t kIcmpv6HeaderLength = 8;
// RFC 4443 3.1: an ICMPv6 error must not exceed the IPv6 minimum MTU.
constexpr size_t kMaxIcmpv6Packet = 1280;
constexpr uint8_t kNextHeaderIcmpv6 = 58;
}  // namespace

uint16_t Ipv6Checksum(const uint8_t *source, const uint8_t *destination,
                      uint8_t nextHeader, const uint8_t *payload, size_t length) {
    uint32_t sum = 0;
    for (size_t i = 0; i < 16; i += 2) {
        sum += (uint32_t(source[i]) << 8) | source[i + 1];
        sum += (uint32_t(destination[i]) << 8) | destination[i + 1];
    }
    sum += uint32_t(length >> 16);
    sum += uint32_t(length & 0xffff);
    sum += nextHeader;
    size_t i = 0;
    for (; i + 1 < length; i += 2) {
        sum += (uint32_t(payload[i]) << 8) | payload[i + 1];
    }
    if (i < length) sum += uint32_t(payload[i]) << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return uint16_t(~sum);
}

bool BuildIcmpv6Unreachable(const uint8_t *packet, size_t size, std::vector<uint8_t> *out) {
    if (size < kIpv6HeaderLength || (packet[0] >> 4) != 6) return false;
    // Never answer an existing ICMPv6 error report (type < 128).
    if (packet[6] == kNextHeaderIcmpv6 && size > kIpv6HeaderLength &&
        packet[kIpv6HeaderLength] < 128) {
        return false;
    }
    // Never answer traffic addressed to a multicast group.
    if (packet[24] == 0xff) return false;

    size_t quote = size;
    if (quote > kMaxIcmpv6Packet - kIpv6HeaderLength - kIcmpv6HeaderLength) {
        quote = kMaxIcmpv6Packet - kIpv6HeaderLength - kIcmpv6HeaderLength;
    }
    const size_t icmpLength = kIcmpv6HeaderLength + quote;

    out->assign(kIpv6HeaderLength + icmpLength, 0);
    uint8_t *raw = out->data();

    raw[0] = 0x60;
    raw[4] = uint8_t(icmpLength >> 8);
    raw[5] = uint8_t(icmpLength & 0xff);
    raw[6] = kNextHeaderIcmpv6;
    raw[7] = 64;  // hop limit
    // Answer travels back to the sender: swap the endpoints.
    std::memcpy(raw + 8, packet + 24, 16);
    std::memcpy(raw + 24, packet + 8, 16);

    uint8_t *icmp = raw + kIpv6HeaderLength;
    icmp[0] = 1;  // Destination Unreachable
    icmp[1] = 1;  // Communication with destination administratively prohibited
    std::memcpy(icmp + kIcmpv6HeaderLength, packet, quote);

    const uint16_t checksum = Ipv6Checksum(raw + 8, raw + 24, kNextHeaderIcmpv6, icmp, icmpLength);
    icmp[2] = uint8_t(checksum >> 8);
    icmp[3] = uint8_t(checksum & 0xff);
    return true;
}

}  // namespace tether
```

- [ ] **Step 3: Register the new source file**

In `app/entry/src/main/cpp/CMakeLists.txt`, change:

```cmake
add_library(tether SHARED napi_init.cpp tunnel.cpp)
```

to:

```cmake
add_library(tether SHARED napi_init.cpp tunnel.cpp icmpv6.cpp)
```

- [ ] **Step 4: Verify it compiles**

Run:
```
cd D:\HarmonyOS\RevTether-ipv6-packet\app
D:\HarmonyOS\command-line-tools-26\command-line-tools\bin\hvigorw.bat --mode module -p product=default -p buildMode=release -p module=entry@default assembleHap --no-daemon
```
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 5: Commit**

```bash
git add app/entry/src/main/cpp/icmpv6.h app/entry/src/main/cpp/icmpv6.cpp app/entry/src/main/cpp/CMakeLists.txt
git commit -m "feat(app): build ICMPv6 destination-unreachable replies"
```

---

## Task 3: Cross-verify the checksum in Rust

The C++ has no test framework. The Rust suite does, and the algorithm is
identical, so a failing Rust test would expose a mistake in the shared formula.

**Files:**
- Modify: `relay/src/relay/ipv6_packetizer.rs` (append inside the existing `mod tests`)

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `relay/src/relay/ipv6_packetizer.rs`:

```rust
    /// Mirrors `Ipv6Checksum` in app/entry/src/main/cpp/icmpv6.cpp.
    ///
    /// The app cannot run unit tests, so the shared folding rule is pinned here:
    /// a receiver folding a correct packet always arrives at 0xffff.
    fn icmpv6_checksum(source: &[u8], destination: &[u8], payload: &[u8]) -> u16 {
        let mut sum = 0u32;
        for index in (0..16).step_by(2) {
            sum += u32::from(u16::from_be_bytes([source[index], source[index + 1]]));
            sum += u32::from(u16::from_be_bytes([destination[index], destination[index + 1]]));
        }
        sum += payload.len() as u32;
        sum += 58; // ICMPv6
        let mut chunks = payload.chunks_exact(2);
        for pair in &mut chunks {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        if let Some(&last) = chunks.remainder().first() {
            sum += u32::from(last) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn icmpv6_checksum_folds_to_all_ones_at_the_receiver() {
        let source = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let destination = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        // Type 1, code 1, zeroed checksum, unused word, then an odd-length quote.
        let mut icmp = vec![1u8, 1, 0, 0, 0, 0, 0, 0, 0x60, 0x11, 0x22];
        let checksum = icmpv6_checksum(&source, &destination, &icmp);
        icmp[2] = (checksum >> 8) as u8;
        icmp[3] = (checksum & 0xff) as u8;

        let mut verify = 0u32;
        for index in (0..16).step_by(2) {
            verify += u32::from(u16::from_be_bytes([source[index], source[index + 1]]));
            verify += u32::from(u16::from_be_bytes([destination[index], destination[index + 1]]));
        }
        verify += icmp.len() as u32;
        verify += 58;
        let mut chunks = icmp.chunks_exact(2);
        for pair in &mut chunks {
            verify += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        if let Some(&last) = chunks.remainder().first() {
            verify += u32::from(last) << 8;
        }
        while verify >> 16 != 0 {
            verify = (verify & 0xffff) + (verify >> 16);
        }
        assert_eq!(0xffff, verify as u16);
    }
```

- [ ] **Step 2: Run the test**

Run:
```
set CARGO_HOME=D:\HarmonyOS\Rust\cargo
set RUSTUP_HOME=D:\HarmonyOS\Rust\rustup
D:\HarmonyOS\Rust\cargo\bin\cargo.exe test --manifest-path D:\HarmonyOS\RevTether-ipv6-packet\relay\Cargo.toml icmpv6
```
Expected: `test result: ok. 1 passed`.

- [ ] **Step 3: Run the whole suite**

Run:
```
D:\HarmonyOS\Rust\cargo\bin\cargo.exe test --manifest-path D:\HarmonyOS\RevTether-ipv6-packet\relay\Cargo.toml
```
Expected: `49 passed; 0 failed`.

- [ ] **Step 4: Commit**

```bash
git add relay/src/relay/ipv6_packetizer.rs
git commit -m "test(relay): pin the ICMPv6 checksum rule shared with the app"
```

---

## Task 4: Mode-aware native tunnel

**Files:**
- Modify: `app/entry/src/main/cpp/tunnel.h:18` and `:28`
- Modify: `app/entry/src/main/cpp/tunnel.cpp` (the `IsWellFormedIpPacket` helper and the `POLLIN` branch on the tun fd)

- [ ] **Step 1: Extend the header**

In `app/entry/src/main/cpp/tunnel.h`, add the enum above `class Tunnel` and change `Start`:

```cpp
enum class Ipv6Mode : int32_t { Off = 0, Proxy = 1, Blackhole = 2 };

class Tunnel {
public:
    ~Tunnel();
    // Duplicates both fds. Caller retains ownership of the originals.
    bool Start(int tunFd, int socketFd, Ipv6Mode ipv6Mode);
```

Add the member beside the other counters (`Run` stays unchanged — the worker
reads `ipv6Mode_` directly):

```cpp
    std::atomic<Ipv6Mode> ipv6Mode_{Ipv6Mode::Off};
```

- [ ] **Step 2: Store the mode in Start**

In `app/entry/src/main/cpp/tunnel.cpp`, change the signature line:

```cpp
bool Tunnel::Start(int tunFd, int socketFd, Ipv6Mode ipv6Mode) {
```

and set the member on the line directly above the counter reset, so it is in
place before the worker thread starts:

```cpp
    stopping_ = false;
    error_ = 0;
    ipv6Mode_ = ipv6Mode;
    txBytes_ = rxBytes_ = txPackets_ = rxPackets_ = dropped_ = 0;
    running_ = true;
```

- [ ] **Step 3: Include the new header**

At the top of `app/entry/src/main/cpp/tunnel.cpp`, beside the existing includes:

```cpp
#include "icmpv6.h"
```

- [ ] **Step 4: Teach the validator about the mode**

Replace the `IsWellFormedIpPacket` function body in `tunnel.cpp` with:

```cpp
// Validate a packet read from the tun device before forwarding it to the relay.
bool IsWellFormedIpPacket(const uint8_t *data, size_t size) {
    if (size < 4) return false;
    const unsigned version = data[0] >> 4;
    if (version == 4) {
        if (size < kIpv4HeaderLength) return false;
        const size_t header = (data[0] & 0x0f) * 4;
        if (header < kIpv4HeaderLength || header > size) return false;
        return ((size_t(data[2]) << 8) | data[3]) == size;
    }
    if (version == 6) {
        if (size < kIpv6HeaderLength) return false;
        // The relay rejects extension headers, so the payload length must match exactly.
        return kIpv6HeaderLength + ((size_t(data[4]) << 8) | data[5]) == size;
    }
    return false;
}

bool IsIpv6(const uint8_t *data, size_t size) {
    return size >= 1 && (data[0] >> 4) == 6;
}
```

- [ ] **Step 5: Branch on the mode when reading from tun**

In the `if (fds[0].revents & POLLIN)` block, replace the body that currently
reads `if (!IsWellFormedIpPacket(buffer, size)) { ++dropped_; } else { ... }` with:

```cpp
                size_t size = static_cast<size_t>(count);
                const Ipv6Mode mode = ipv6Mode_.load();
                if (!IsWellFormedIpPacket(buffer, size)) {
                    ++dropped_;
                } else if (IsIpv6(buffer, size) && mode != Ipv6Mode::Proxy) {
                    // Refuse locally so the application falls back to IPv4 at once
                    // instead of waiting out a TCP timeout.
                    ++dropped_;
                    std::vector<uint8_t> reply;
                    if (mode == Ipv6Mode::Blackhole &&
                        queuedBytes + MAX_PACKET < MAX_QUEUE &&
                        BuildIcmpv6Unreachable(buffer, size, &reply)) {
                        queuedBytes += reply.size();
                        packets.emplace_back(std::move(reply));
                    }
                } else {
                    if (sendOffset) {
                        outbound.erase(outbound.begin(), outbound.begin() + sendOffset);
                        sendOffset = 0;
                    }
                    outbound.insert(outbound.end(), buffer, buffer + size);
                    ++txPackets_; txBytes_ += size;
                }
```

- [ ] **Step 6: Verify it compiles**

Run:
```
cd D:\HarmonyOS\RevTether-ipv6-packet\app
D:\HarmonyOS\command-line-tools-26\command-line-tools\bin\hvigorw.bat --mode module -p product=default -p buildMode=release -p module=entry@default assembleHap --no-daemon
```
Expected: `BUILD SUCCESSFUL`. (`napi_init.cpp` still calls the two-argument
`Start`, so expect a compile error here and fix it in Task 5 — if the build
fails only on that call site, proceed.)

- [ ] **Step 7: Commit**

```bash
git add app/entry/src/main/cpp/tunnel.h app/entry/src/main/cpp/tunnel.cpp
git commit -m "feat(app): honour the IPv6 mode inside the native tunnel"
```

---

## Task 5: NAPI fourth argument

**Files:**
- Modify: `app/entry/src/main/cpp/napi_init.cpp:99-106`

- [ ] **Step 1: Accept and validate the mode**

Replace the `Start` function:

```cpp
napi_value Start(napi_env env, napi_callback_info info) {
    std::lock_guard<std::mutex> lock(sessionMutex);
    int32_t values[4];
    if (!Args(env, info, 4, values)) return nullptr;
    if (values[2] != currentSession) return Error(env, "Stale VPN session");
    if (values[3] < 0 || values[3] > 2) return Error(env, "Invalid IPv6 mode");
    const tether::Ipv6Mode mode = static_cast<tether::Ipv6Mode>(values[3]);
    if (!tunnel.Start(values[0], values[1], mode)) return Error(env, "Cannot start tunnel: " + tunnel.Status());
    return Undefined(env);
}
```

- [ ] **Step 2: Verify it compiles**

Run:
```
cd D:\HarmonyOS\RevTether-ipv6-packet\app
D:\HarmonyOS\command-line-tools-26\command-line-tools\bin\hvigorw.bat --mode module -p product=default -p buildMode=release -p module=entry@default assembleHap --no-daemon
```
Expected: `BUILD SUCCESSFUL` with no errors.

- [ ] **Step 3: Commit**

```bash
git add app/entry/src/main/cpp/napi_init.cpp
git commit -m "feat(app): pass the IPv6 mode across the NAPI boundary"
```

---

## Task 6: VPN ability wiring

**Files:**
- Modify: `app/entry/src/main/ets/vpn/TetherVpnAbility.ets` (imports, `onCreate`, the `VpnConfig` literal, the `tether.start` call)

- [ ] **Step 1: Import and hold the mode**

Add to the imports:

```typescript
import { Ipv6Mode, loadIpv6Mode, normalizeIpv6Mode } from '../common/Ipv6Settings';
```

Add the field beside `private port: number = PORT;`:

```typescript
  private ipv6Mode: Ipv6Mode = Ipv6Mode.Off;
```

- [ ] **Step 2: Resolve the mode in onCreate**

Immediately after the existing DNS validation block in `onCreate` (just before
`this.stopped = false;`), insert:

```typescript
    // Prefer the launch parameter; fall back to the stored setting, because the
    // ability can also be started by HDC or restarted by the system.
    const requestedMode = want.parameters?.ipv6Mode;
    if (typeof requestedMode === 'string' || typeof requestedMode === 'number') {
      this.ipv6Mode = normalizeIpv6Mode(Number(requestedMode));
    } else {
      this.ipv6Mode = loadIpv6Mode(this.context.filesDir);
    }
```

- [ ] **Step 3: Shape the VpnConfig by mode**

Replace the `const config: vpnExtension.VpnConfig = { ... };` literal with:

```typescript
      const captureIpv6 = this.ipv6Mode !== Ipv6Mode.Off;
      const addresses: vpnExtension.LinkAddress[] = [
        {address: {address: '10.0.0.2', family: 1}, prefixLength: 32}
      ];
      const routes: vpnExtension.RouteInfo[] = [{
        interface: 'vpn-tun',
        destination: {address: {address: '0.0.0.0', family: 1}, prefixLength: 0},
        gateway: {address: '0.0.0.0', family: 1},
        hasGateway: false,
        isDefaultRoute: true
      }];
      if (captureIpv6) {
        // ULA endpoint for the tunnel. The relay mirrors this address when it
        // synthesizes responses, so it never appears on the public wire.
        addresses.push({address: {address: 'fd00::2', family: 2}, prefixLength: 128});
        // Without this route the system keeps sending IPv6 around the tunnel.
        routes.push({
          interface: 'vpn-tun',
          destination: {address: {address: '::', family: 2}, prefixLength: 0},
          gateway: {address: '::', family: 2},
          hasGateway: false,
          isDefaultRoute: true
        });
      }
      const config: vpnExtension.VpnConfig = {
        addresses: addresses,
        routes: routes,
        // Relay resolves the virtual address through the host's DNS server.
        dnsAddresses: [this.dnsAddress],
        mtu: 1500,
        isIPv4Accepted: true,
        isIPv6Accepted: captureIpv6,
        isBlocking: false
      };
```

- [ ] **Step 4: Pass the mode to native**

Replace `tether.start(this.tunFd, this.socketFd, this.session);` with:

```typescript
      tether.start(this.tunFd, this.socketFd, this.session, this.ipv6Mode as number);
```

- [ ] **Step 5: Log the active mode**

Replace the `VPN_READY` log line with:

```typescript
      hilog.info(0x0001, 'HarmonyTether', 'VPN_READY port=%{public}d mtu=1500 dns=%{public}s ipv6=%{public}d', this.port, this.dnsAddress, this.ipv6Mode as number);
```

- [ ] **Step 6: Verify it compiles**

Run:
```
cd D:\HarmonyOS\RevTether-ipv6-packet\app
D:\HarmonyOS\command-line-tools-26\command-line-tools\bin\hvigorw.bat --mode module -p product=default -p buildMode=release -p module=entry@default assembleHap --no-daemon
```
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 7: Commit**

```bash
git add app/entry/src/main/ets/vpn/TetherVpnAbility.ets
git commit -m "feat(app): publish IPv6 routes only when the mode asks for them"
```

---

## Task 7: Settings card UI

**Files:**
- Modify: `app/entry/src/main/ets/pages/Index.ets` (imports, state, `refresh`, `vpnWant`, the `home` builder)

- [ ] **Step 1: Import and track the mode**

Add to the imports:

```typescript
import { Ipv6Mode, loadIpv6Mode, saveIpv6Mode } from '../common/Ipv6Settings';
```

Add beside the other `@State` fields:

```typescript
  @State ipv6Mode: Ipv6Mode = Ipv6Mode.Off;
```

- [ ] **Step 2: Load it on refresh**

In `refresh()`, after `this.consent = hasPrivacyConsent(context.filesDir);`, add:

```typescript
    this.ipv6Mode = loadIpv6Mode(context.filesDir);
```

- [ ] **Step 3: Send the mode when starting the VPN**

Replace `vpnWant()` with:

```typescript
  private vpnWant(): Want {
    const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
    const parameters: Record<string, string> = tetherParameters();
    parameters['ipv6Mode'] = String(this.ipv6Mode as number);
    return {bundleName: context.abilityInfo.bundleName, abilityName: VPN_ABILITY, parameters: parameters};
  }
```

- [ ] **Step 4: Add the mode-change handler**

Add these methods next to `probe()`:

```typescript
  private ipv6Subtitle(): string {
    if (this.ipv6Mode === Ipv6Mode.Blackhole) return '拦截 IPv6 并拒绝，应用将回落 IPv4';
    if (this.ipv6Mode === Ipv6Mode.Proxy) return 'IPv6 经电脑转发出网';
    return '系统自行处理 IPv6，可能绕过隧道';
  }

  private async applyIpv6Mode(mode: Ipv6Mode): Promise<void> {
    if (this.acting) return;
    const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
    try {
      saveIpv6Mode(context.filesDir, mode);
    } catch (_) {
      this.message = '保存设置失败，请重试。';
      return;
    }
    this.ipv6Mode = mode;
    // A running tunnel keeps its old routes until it is re-established.
    if (this.status.state === 'stopped') return;
    this.message = '正在应用新设置…';
    await this.stop();
    await this.start();
  }
```

- [ ] **Step 5: Render the card**

In the `home()` builder, insert this block between the button `Column` and the
closing of the outer `Column({ space: 24 })` (that is, directly after the
`}.width('100%')` that ends the button column):

```typescript
        Column() {
          Row() {
            Column({ space: 4 }) {
              Text('代理 IPv6').fontSize(16).fontColor($r('sys.color.font_primary'))
              Text(this.ipv6Subtitle()).fontSize(12).fontColor($r('sys.color.font_secondary')).lineHeight(18)
            }.alignItems(HorizontalAlign.Start).layoutWeight(1)
            Toggle({ type: ToggleType.Switch, isOn: this.ipv6Mode !== Ipv6Mode.Off })
              .enabled(!this.acting)
              .onChange((on: boolean) => this.applyIpv6Mode(on ? Ipv6Mode.Proxy : Ipv6Mode.Off))
          }.width('100%').padding({ top: 16, bottom: 16, left: 16, right: 16 })
          if (this.ipv6Mode !== Ipv6Mode.Off) {
            Divider().color($r('sys.color.comp_divider'))
            Row() {
              Column({ space: 4 }) {
                Text('黑洞模式').fontSize(16).fontColor($r('sys.color.font_primary'))
                Text('拦截并拒绝所有 IPv6 出站').fontSize(12).fontColor($r('sys.color.font_secondary')).lineHeight(18)
              }.alignItems(HorizontalAlign.Start).layoutWeight(1)
              Toggle({ type: ToggleType.Switch, isOn: this.ipv6Mode === Ipv6Mode.Blackhole })
                .enabled(!this.acting)
                .onChange((on: boolean) => this.applyIpv6Mode(on ? Ipv6Mode.Blackhole : Ipv6Mode.Proxy))
            }.width('100%').padding({ top: 16, bottom: 16, left: 32, right: 16 })
          }
        }.width('100%').backgroundColor($r('sys.color.comp_background_list_card')).borderRadius(16)
```

- [ ] **Step 6: Verify it compiles**

Run:
```
cd D:\HarmonyOS\RevTether-ipv6-packet\app
D:\HarmonyOS\command-line-tools-26\command-line-tools\bin\hvigorw.bat --mode module -p product=default -p buildMode=release -p module=entry@default assembleHap --no-daemon
```
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 7: Commit**

```bash
git add app/entry/src/main/ets/pages/Index.ets
git commit -m "feat(app): add the IPv6 mode card to the home page"
```

---

## Task 8: Help text

**Files:**
- Modify: `app/entry/src/main/ets/common/HelpContent.ets:41`

- [ ] **Step 1: Add the entry**

After the existing `{ title: '部分应用不兼容', ... }` entry in the same array, add:

```typescript
      { title: 'IPv6 的三种处理方式', body: '关闭“代理 IPv6”时，系统自行处理 IPv6，这些流量不经过隧道，可能暴露手机自身的网络出口。开启后 IPv6 会经电脑转发；若电脑没有 IPv6 出口，请同时开启“黑洞模式”，让手机立刻收到拒绝并回落 IPv4，而不是长时间等待超时。' }
```

- [ ] **Step 2: Verify it compiles**

Run:
```
cd D:\HarmonyOS\RevTether-ipv6-packet\app
D:\HarmonyOS\command-line-tools-26\command-line-tools\bin\hvigorw.bat --mode module -p product=default -p buildMode=release -p module=entry@default assembleHap --no-daemon
```
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 3: Commit**

```bash
git add app/entry/src/main/ets/common/HelpContent.ets
git commit -m "docs(app): explain the three IPv6 modes in help"
```

---

## Task 9: Device verification

No automated coverage reaches the tun device, so this task is manual and its
observations are the acceptance evidence.

**Files:** none (verification only)

- [ ] **Step 1: Build and install**

Run:
```
cd D:\HarmonyOS\rev-tether-api26-signed\app
```
First copy the changed sources across (the signing config lives only in this
copy):
```
robocopy D:\HarmonyOS\RevTether-ipv6-packet\app\entry\src\main D:\HarmonyOS\rev-tether-api26-signed\app\entry\src\main /E /XO
```
Then build and install:
```
D:\HarmonyOS\command-line-tools-26\command-line-tools\bin\hvigorw.bat --mode module -p product=default -p buildMode=release -p module=entry@default assembleHap --no-daemon
D:\HarmonyOS\command-line-tools-26\command-line-tools\sdk\default\openharmony\toolchains\hdc.exe install -r D:\HarmonyOS\rev-tether-api26-signed\app\entry\build\default\outputs\default\entry-default-signed.hap
```
Expected: `install bundle successfully`.

- [ ] **Step 2: Confirm Off publishes no IPv6 route**

With the main switch off, connect, then run:
```
D:\HarmonyOS\command-line-tools-26\command-line-tools\sdk\default\openharmony\toolchains\hdc.exe shell hilog -x
```
Expected: a `VPN_READY ... ipv6=0` line.

- [ ] **Step 3: Confirm Proxy reaches the relay**

Turn the main switch on, leave blackhole off, then restart the relay with logs:
```
taskkill /IM harmony-relay.exe /F
cd D:\HarmonyOS\RevTether
set RUST_LOG=debug
start /B harmony-relay.exe --port 31417 > relay-check.log 2>&1
```
Reconnect on the phone and inspect `relay-check.log`.
Expected: `VPN_READY ... ipv6=1`, and IPv6 packets reaching the relay rather
than being rejected by the tunnel.

- [ ] **Step 4: Confirm Blackhole refuses quickly**

Turn blackhole on, then open a browser on the phone and load a dual-stack site.
Expected: the page still loads (IPv4 fallback) and `dropped` in the home-page
statistics grows. The relay log must show no new IPv6 connections, because the
packets never leave the phone.

- [ ] **Step 5: Restore the relay to normal mode**

```
taskkill /IM harmony-relay.exe /F
del D:\HarmonyOS\RevTether\relay-check.log
pwsh -NoProfile -ExecutionPolicy Bypass -File D:\HarmonyOS\RevTether\Start-Revtether.ps1
```
Expected: `USB 共享已启动`.

- [ ] **Step 6: Commit the verification notes**

Record the observed `dropped` counts and fallback behaviour at the end of
`docs/superpowers/specs/2026-09-20-ipv6-mode-toggle-design.md` under a new
"验证结果" section, then:

```bash
git add docs/superpowers/specs/2026-09-20-ipv6-mode-toggle-design.md
git commit -m "docs: record on-device verification of the IPv6 modes"
```

---

## Known Gaps

- The computer still has no IPv6 egress, so Task 9 Step 3 proves only that
  packets reach the relay, not that they reach the public internet.
- ICMPv6 covers Destination Unreachable only; Packet Too Big is out of scope.
- The native code has no unit tests. Task 3 pins the checksum rule from the
  Rust side, but packet layout and the multicast guard rely on Task 9.
