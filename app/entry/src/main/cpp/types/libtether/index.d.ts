export const createSocket: () => number;
export const connect: (socketFd: number, port: number) => Promise<void>;
// ipv6Mode: 0 = off, 1 = proxy, 2 = blackhole (see common/Ipv6Settings.ets).
export const start: (tunFd: number, socketFd: number, session: number, ipv6Mode: number) => void;
export const stop: (session: number) => void;
export const close: (fd: number) => void;
export const status: (session: number) => string;
export const newSession: () => number;
