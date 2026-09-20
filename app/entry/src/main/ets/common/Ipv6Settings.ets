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
