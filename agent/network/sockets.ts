import { devlog, am_send } from "../utils/logging.js"
import { Where } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"
import { safeDeferred, safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"
import { safeAttachExport } from "../utils/safe_native.js"


/**
 * 
 * Some parts are taken from https://github.com/Areizen/Android-Malware-Sandbox/blob/master/frida_scripts/lib/hooks.js
 * https://codeshare.frida.re/@mame82/android-tcp-trace/
 * 
 * must still be extended for UDP
 */

const PROFILE_HOOKING_TYPE: string = "NETWORK_SOCKETS"

const AF_INET = 2;
const AF_INET6 = 10;

const SOCK_STREAM = 1;
const SOCK_DGRAM = 2;

interface NativeSocketState {
    socketType: string;
    addressFamily?: number;
    protocol?: number;
}

const nativeSocketStates = new Map<number, NativeSocketState>();

function createSocketEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function getStackTrace() {
    const threadDef = Java.use("java.lang.Thread");
    const threadInstance = threadDef.$new();

    return Where(threadInstance.currentThread().getStackTrace());
}

// we need this in order to handle the compiling 
function isTcpEndpointAddress(
    address: SocketEndpointAddress
): address is TcpEndpointAddress {
    return "ip" in address;
}

function getSocketTypeFromArguments(
    addressFamily: number,
    socketType: number
): string | null {
    const baseType = socketType & 0x0f;

    if (addressFamily === AF_INET) {
        if (baseType === SOCK_STREAM) return "tcp";
        if (baseType === SOCK_DGRAM) return "udp";
    }

    if (addressFamily === AF_INET6) {
        if (baseType === SOCK_STREAM) return "tcp6";
        if (baseType === SOCK_DGRAM) return "udp6";
    }

    return null;
}

function isInetSocketType(socketType: string): boolean {
    return socketType === "tcp" ||
        socketType === "tcp6" ||
        socketType === "udp" ||
        socketType === "udp6";
}

function trackNativeSocket(
    socketDescriptor: number,
    socketType: string,
    addressFamily?: number,
    protocol?: number
): NativeSocketState {
    const existingState = nativeSocketStates.get(socketDescriptor);

    if (existingState) {
        return existingState;
    }

    const state: NativeSocketState = {
        socketType: socketType,
        addressFamily: addressFamily,
        protocol: protocol
    };

    nativeSocketStates.set(socketDescriptor, state);

    createSocketEvent("socket.native.created", {
        method: "socket",
        socket_descriptor: socketDescriptor,
        socket_type: socketType,
        address_family: addressFamily,
        protocol: protocol
    });

    return state;
}

function trackSocketFromRuntime(
    socketDescriptor: number
): NativeSocketState | null {
    const existingState = nativeSocketStates.get(socketDescriptor);

    if (existingState) {
        return existingState;
    }

    try {
        const socketType = Socket.type(socketDescriptor);

        if (!socketType || !isInetSocketType(socketType)) {
            return null;
        }

        const state: NativeSocketState = {
            socketType: socketType
        };

        // The descriptor was first observed after creation. Keep state for
        // later events without emitting a creation event not directly seen.
        nativeSocketStates.set(socketDescriptor, state);

        return state;
    } catch (_) {
        return null;
    }
}

function trackAcceptedSocket(
    listeningDescriptor: number,
    acceptedDescriptor: number
): void {
    if (acceptedDescriptor < 0 || nativeSocketStates.has(acceptedDescriptor)) {
        return;
    }

    const listeningState =
        nativeSocketStates.get(listeningDescriptor) ||
        trackSocketFromRuntime(listeningDescriptor);

    if (listeningState) {
        nativeSocketStates.set(acceptedDescriptor, {
            socketType: listeningState.socketType,
            addressFamily: listeningState.addressFamily,
            protocol: listeningState.protocol
        });

        return;
    }

    // Fallback for a listening socket that existed before agent attachment.
    trackSocketFromRuntime(acceptedDescriptor);
}

function hook_java_socket_communication() {
    safePerform("sockets:hook_java_socket_communication", () => {
        const ServerSocket = safeUse(
            "java.net.ServerSocket",
            "sockets:hook_java_socket_communication"
        );
        const Socket = safeUse(
            "java.net.Socket",
            "sockets:hook_java_socket_communication"
        );
        const LocalServerSocket = safeUse(
            "android.net.LocalServerSocket",
            "sockets:hook_java_socket_communication"
        );
        const DatagramSocket = safeUse(
            "java.net.DatagramSocket",
            "sockets:hook_java_socket_communication"
        );

        if (ServerSocket) {
            const accept = safeOverload(
                ServerSocket.accept,
                "sockets:ServerSocket.accept"
            );

            if (accept) {
                accept.implementation = safeImplementation(
                    "sockets:ServerSocket.accept",
                    accept,
                    function(original) {
                        const result = original.call(this);

                        createSocketEvent("socket.java.server_accept", {
                            class: "java.net.ServerSocket",
                            method: "accept",
                            server_info: this.toString(),
                            stack_trace: getStackTrace()
                        });

                        return result;
                    }
                );
            }
        }

        if (Socket) {
            const socketInit = safeOverload(
                Socket.$init,
                "sockets:Socket.$init",
                "java.lang.String",
                "int"
            );

            if (socketInit) {
                socketInit.implementation = safeImplementation(
                    "sockets:Socket.$init",
                    socketInit,
                    function(original, host, port) {
                        const result = original.call(this, host, port);

                        createSocketEvent("socket.java.init", {
                            class: "java.net.Socket",
                            method: "$init",
                            host: host,
                            port: port,
                            connection_string: `${host}:${port}`,
                            stack_trace: getStackTrace()
                        });

                        return result;
                    }
                );
            }

            const connectWithTimeout = safeOverload(
                Socket.connect,
                "sockets:Socket.connect",
                "java.net.SocketAddress",
                "int"
            );

            if (connectWithTimeout) {
                connectWithTimeout.implementation = safeImplementation(
                    "sockets:Socket.connect[SocketAddress,int]",
                    connectWithTimeout,
                    function(original, endpoint, timeout) {
                        const result = original.call(this, endpoint, timeout);

                        createSocketEvent("socket.java.connect", {
                            class: "java.net.Socket",
                            method: "connect",
                            endpoint: endpoint.toString(),
                            timeout: timeout,
                            stack_trace: getStackTrace()
                        });

                        return result;
                    }
                );
            }

            const connectBasic = safeOverload(
                Socket.connect,
                "sockets:Socket.connect",
                "java.net.SocketAddress"
            );

            if (connectBasic) {
                connectBasic.implementation = safeImplementation(
                    "sockets:Socket.connect[SocketAddress]",
                    connectBasic,
                    function(original, endpoint) {
                        const result = original.call(this, endpoint);

                        createSocketEvent("socket.java.connect", {
                            class: "java.net.Socket",
                            method: "connect",
                            endpoint: endpoint.toString(),
                            stack_trace: getStackTrace()
                        });

                        return result;
                    }
                );
            }
        }

        if (LocalServerSocket) {
            const localAccept = safeOverload(
                LocalServerSocket.accept,
                "sockets:LocalServerSocket.accept"
            );

            if (localAccept) {
                localAccept.implementation = safeImplementation(
                    "sockets:LocalServerSocket.accept",
                    localAccept,
                    function(original) {
                        const result = original.call(this);

                        createSocketEvent("socket.java.local_accept", {
                            class: "android.net.LocalServerSocket",
                            method: "accept",
                            server_info: this.toString(),
                            stack_trace: getStackTrace()
                        });

                        return result;
                    }
                );
            }
        }

        if (DatagramSocket) {
            const datagramConnect = safeOverload(
                DatagramSocket.connect,
                "sockets:DatagramSocket.connect",
                "java.net.InetAddress",
                "int"
            );

            if (datagramConnect) {
                datagramConnect.implementation = safeImplementation(
                    "sockets:DatagramSocket.connect",
                    datagramConnect,
                    function(original, address, port) {
                        const result = original.call(this, address, port);

                        createSocketEvent("socket.java.datagram_connect", {
                            class: "java.net.DatagramSocket",
                            method: "connect",
                            address: address.toString(),
                            port: port,
                            connection_string: `${address}:${port}`,
                            stack_trace: getStackTrace()
                        });

                        return result;
                    }
                );
            }
        }
    });
}


function hook_bionic_socket_communication(){
    // TCP/UDP functions in libc.so. Each symbol is resolved and hooked
    // via safeAttachExport independently so a missing symbol does not
    // abort the full install

    // helper function
    function swap16(value) {
        return ((value & 0xFF) << 8) |
            ((value >> 8) & 0xFF);
    }

    safeAttachExport("libc.so", "socket", "sockets:socket", {
        onEnter(args) {
            this.addressFamily = args[0].toInt32();
            this.socketType = args[1].toInt32();
            this.protocol = args[2].toInt32();
        },
        onLeave(retval) {
            const socketDescriptor = retval.toInt32();

            if (socketDescriptor < 0) {
                return;
            }

            const socketType = getSocketTypeFromArguments(
                this.addressFamily,
                this.socketType
            );

            if (!socketType) {
                return;
            }

            trackNativeSocket(
                socketDescriptor,
                socketType,
                this.addressFamily,
                this.protocol
            );
        }
    });

    safeAttachExport("libc.so", "bind", "sockets:bind", {
        onEnter(args) {
            this.sd = args[0].toInt32();
            this.addr = args[1];
            this.addrlen = args[2].toInt32();
        },
        onLeave(retval) {
            if (retval.toInt32() !== 0) {
                return;
            }

            const socketState = trackSocketFromRuntime(this.sd);
            const socketType = socketState?.socketType;

            if (!socketType || !isInetSocketType(socketType)) {
                return;
            }

            const socketLocal = Socket.localAddress(this.sd);

            if (!isTcpEndpointAddress(socketLocal)) {
                return;
            }

            createSocketEvent("socket.native.bind", {
                method: "bind",
                socket_descriptor: this.sd,
                socket_type: socketType,
                address_family: socketState?.addressFamily,
                protocol: socketState?.protocol,
                result_code: 0,
                local_ip: socketLocal.ip,
                local_port: socketLocal.port
            });
        }
    });

    safeAttachExport("libc.so", "connect", "sockets:connect", {
        onEnter(args) {
            this.sd = args[0].toInt32();
        },
        onLeave(retval) {
            const resultCode = retval.toInt32();

            if (resultCode !== 0) {
                return;
            }

            const socketState = trackSocketFromRuntime(this.sd);
            const socketType = socketState?.socketType;

            if (!socketType) {
                return;
            }

            const socketLocal = Socket.localAddress(this.sd);
            const local = socketLocal && isTcpEndpointAddress(socketLocal)
                ? socketLocal
                : undefined;

            const socketRemote = Socket.peerAddress(this.sd);
            const remote = socketRemote && isTcpEndpointAddress(socketRemote)
                ? socketRemote
                : undefined;

            // Do not emit raw endpoint objects without an event_type.
            if (!local || !remote) {
                return;
            }

            createSocketEvent("socket.native.connect", {
                method: "connect",
                socket_descriptor: this.sd,
                socket_type: socketType,
                address_family: socketState?.addressFamily,
                protocol: socketState?.protocol,
                result_code: resultCode,
                local_ip: local.ip,
                local_port: local.port,
                remote_ip: remote.ip,
                remote_port: remote.port
            });
        }
    });

    safeAttachExport("libc.so", "accept", "sockets:accept", {
        onEnter(args) {
            this.listeningDescriptor = args[0].toInt32();
        },
        onLeave(retval) {
            trackAcceptedSocket(
                this.listeningDescriptor,
                retval.toInt32()
            );
        }
    });

    safeAttachExport("libc.so", "accept4", "sockets:accept4", {
        onEnter(args) {
            this.listeningDescriptor = args[0].toInt32();
        },
        onLeave(retval) {
            trackAcceptedSocket(
                this.listeningDescriptor,
                retval.toInt32()
            );
        }
    });

    safeAttachExport("libc.so", "write", "sockets:write", {
        onEnter(args) {
            this.sd = args[0].toInt32();
            this.addr = args[1];
            this.buflen = args[2].toInt32();
        },
        onLeave(retval) {
            const len = retval.toInt32();

            if (len === -1 || len > this.buflen) {
                return;
            }

            const socketType = Socket.type(this.sd);
            const socketLocal = Socket.localAddress(this.sd);
            const local = socketLocal && isTcpEndpointAddress(socketLocal)
                ? socketLocal
                : undefined;
            const socketRemote = Socket.peerAddress(this.sd);
            const remote = socketRemote && isTcpEndpointAddress(socketRemote)
                ? socketRemote
                : undefined;

            if (
                socketType === "unix:stream" ||
                socketType == null ||
                local === undefined ||
                remote === undefined
            ) {
                return;
            }

            trackSocketFromRuntime(this.sd);

            let buffer;
            const buf = ptr(this.addr);

            if (!buf.isNull()) {
                buffer = buf.readByteArray(len);
            }

            createSocketEvent("socket.native.write", {
                method: "write",
                socket_descriptor: this.sd,
                socket_type: socketType,
                local_ip: local.ip,
                local_port: local.port,
                remote_ip: remote.ip,
                remote_port: remote.port,
                data_length: len,
                has_buffer: buffer !== undefined
            });

            if (buffer) {
                am_send(PROFILE_HOOKING_TYPE, JSON.stringify({
                    event_type: "socket.native.write_data",
                    timestamp: Date.now(),
                    socket_descriptor: this.sd,
                    data_length: len
                }), buffer);
            }
        }
    });

    function hookNativeRead() {
        safeAttachExport("libc.so", "read", "sockets:read", {
            onEnter(args) {
                this.sd = args[0].toInt32();
                this.addr = args[1];
                this.buflen = args[2].toInt32();
            },
            onLeave(retval) {
                const len = retval.toInt32();

                if (len === -1 || len > this.buflen) {
                    return;
                }

                const socketType = Socket.type(this.sd);
                const socketLocal = Socket.localAddress(this.sd);
                const local = socketLocal && isTcpEndpointAddress(socketLocal)
                    ? socketLocal
                    : undefined;
                const socketRemote = Socket.peerAddress(this.sd);
                const remote = socketRemote && isTcpEndpointAddress(socketRemote)
                    ? socketRemote
                    : undefined;

                if (
                    socketType === "unix:stream" ||
                    socketType == null ||
                    local === undefined ||
                    remote === undefined
                ) {
                    return;
                }

                trackSocketFromRuntime(this.sd);

                let buffer;
                const buf = ptr(this.addr);

                if (!buf.isNull()) {
                    buffer = buf.readByteArray(len);
                }

                createSocketEvent("socket.native.read", {
                    method: "read",
                    socket_descriptor: this.sd,
                    socket_type: socketType,
                    local_ip: local.ip,
                    local_port: local.port,
                    remote_ip: remote.ip,
                    remote_port: remote.port,
                    data_length: len,
                    has_buffer: buffer !== undefined
                });

                if (buffer) {
                    am_send(PROFILE_HOOKING_TYPE, JSON.stringify({
                        event_type: "socket.native.read_data",
                        timestamp: Date.now(),
                        socket_descriptor: this.sd,
                        data_length: len
                    }), buffer);
                }
            }
        });
    }

    setTimeout(
        safeDeferred("sockets:read:delayed_install", () => {
            devlog("Installing delayed libc read hook");
            hookNativeRead();
        }),
        2000
    );

    safeAttachExport("libc.so", "sendto", "sockets:sendto", {
        onEnter(args) {
            this.sd = args[0].toInt32();
            this.addr = args[1];
            this.buflen = args[2].toInt32();
            this.ipAddr = args[4];
        },
        onLeave(retval) {
            const len = retval.toInt32();

            if (len === -1 || len > this.buflen) {
                return;
            }

            const socketType = Socket.type(this.sd);
            const socketLocal = Socket.localAddress(this.sd);
            const local = socketLocal && isTcpEndpointAddress(socketLocal)
                ? socketLocal
                : undefined;

            if (
                socketType === "unix:stream" ||
                socketType == null ||
                local === undefined
            ) {
                return;
            }

            trackSocketFromRuntime(this.sd);

            let buffer;
            const buf = ptr(this.addr);

            if (!buf.isNull()) {
                buffer = buf.readByteArray(len);
            }

            if (this.ipAddr.toInt32() === 0) {
                const socketRemote = Socket.peerAddress(this.sd);
                const remote = socketRemote && isTcpEndpointAddress(socketRemote)
                    ? socketRemote
                    : undefined;

                if (remote === undefined) {
                    return;
                }

                createSocketEvent("socket.native.sendto", {
                    method: "sendto",
                    socket_descriptor: this.sd,
                    socket_type: socketType,
                    local_ip: local.ip,
                    local_port: local.port,
                    remote_ip: remote.ip,
                    remote_port: remote.port,
                    data_length: len,
                    has_buffer: buffer !== undefined
                });

                if (buffer) {
                    am_send(PROFILE_HOOKING_TYPE, JSON.stringify({
                        event_type: "socket.native.sendto_data",
                        timestamp: Date.now(),
                        socket_descriptor: this.sd,
                        data_length: len
                    }), buffer);
                }

                return;
            }

            const destAddr = ptr(this.ipAddr);

            if (destAddr.isNull()) {
                return;
            }

            const family = destAddr.readS16();

            // Historical behavior retained for S1.2 normalization.
            if (family === 1) {
                const port = swap16(destAddr.add(2).readU16());

                const addrB0 = destAddr.add(4).readU8();
                const addrB1 = destAddr.add(5).readU8();
                const addrB2 = destAddr.add(6).readU8();
                const addrB3 = destAddr.add(7).readU8();
                const ipString =
                    `${addrB0}.${addrB1}.${addrB2}.${addrB3}`;

                createSocketEvent("socket.native.sendto", {
                    method: "sendto",
                    socket_descriptor: this.sd,
                    socket_type: socketType,
                    local_ip: local.ip,
                    local_port: local.port,
                    remote_ip: ipString,
                    remote_port: port,
                    address_family: family,
                    data_length: len,
                    has_buffer: buffer !== undefined
                });

                if (buffer) {
                    am_send(PROFILE_HOOKING_TYPE, JSON.stringify({
                        event_type: "socket.native.sendto_data",
                        timestamp: Date.now(),
                        socket_descriptor: this.sd,
                        data_length: len
                    }), buffer);
                }
            }
        }
    });

    safeAttachExport("libc.so", "recvfrom", "sockets:recvfrom", {
        onEnter(args) {
            this.sd = args[0].toInt32();
            this.addr = args[1];
            this.buflen = args[2].toInt32();
            this.ipAddr = args[4];
        },
        onLeave(retval) {
            const len = retval.toInt32();

            if (len === -1 || len > this.buflen) {
                return;
            }

            let buffer;
            const buf = ptr(this.addr);

            if (!buf.isNull()) {
                buffer = buf.readByteArray(len);
            }

            const socketType = Socket.type(this.sd);
            const socketLocal = Socket.localAddress(this.sd);
            const local = socketLocal && isTcpEndpointAddress(socketLocal)
                ? socketLocal
                : undefined;

            if (
                socketType === "unix:stream" ||
                socketType == null ||
                local === undefined
            ) {
                return;
            }

            trackSocketFromRuntime(this.sd);

            if (this.ipAddr.toInt32() === 0) {
                const socketRemote = Socket.peerAddress(this.sd);
                const remote = socketRemote && isTcpEndpointAddress(socketRemote)
                    ? socketRemote
                    : undefined;

                if (remote === undefined) {
                    return;
                }

                const data = {
                    event_type: "Libc::recvfrom",
                    method: "recvfrom",
                    sd: this.sd,
                    src_ip: remote.ip,
                    src_port: remote.port,
                    dst_ip: local.ip,
                    dst_port: local.port,
                    len: len,
                    type: socketType
                };

                am_send(PROFILE_HOOKING_TYPE, JSON.stringify(data), buffer);
                return;
            }

            const srcAddr = ptr(this.ipAddr);

            if (srcAddr.isNull()) {
                return;
            }

            const family = srcAddr.readS16();

            // Historical behavior retained for S1.2 normalization.
            if (family === 1) {
                const port = swap16(srcAddr.add(2).readU16());

                const addrB0 = srcAddr.add(4).readU8();
                const addrB1 = srcAddr.add(5).readU8();
                const addrB2 = srcAddr.add(6).readU8();
                const addrB3 = srcAddr.add(7).readU8();
                const ipString =
                    `${addrB0}.${addrB1}.${addrB2}.${addrB3}`;

                const data = {
                    event_type: "Libc::recvfrom",
                    method: "recvfrom",
                    sd: this.sd,
                    len: len,
                    src_ip: local.ip,
                    src_port: local.port,
                    dst_ip: ipString,
                    dst_port: port,
                    dst_family: family,
                    type: socketType
                };

                am_send(PROFILE_HOOKING_TYPE, JSON.stringify(data), buffer);
            }
        }
    });

    safeAttachExport("libc.so", "send", "sockets:send", {
        onEnter(args) {
            this.sd = args[0].toInt32();
            this.addr = args[1];
            this.buflen = args[2].toInt32();
        },
        onLeave(retval) {
            const len = retval.toInt32();

            if (len <= 0 || len > this.buflen) {
                return;
            }

            const socketState = trackSocketFromRuntime(this.sd);

            if (!socketState || !isInetSocketType(socketState.socketType)) {
                return;
            }

            const socketLocal = Socket.localAddress(this.sd);
            const local = socketLocal && isTcpEndpointAddress(socketLocal)
                ? socketLocal
                : undefined;
            const socketRemote = Socket.peerAddress(this.sd);
            const remote = socketRemote && isTcpEndpointAddress(socketRemote)
                ? socketRemote
                : undefined;

            if (local === undefined || remote === undefined) {
                return;
            }

            let buffer;
            const buf = ptr(this.addr);

            if (!buf.isNull()) {
                buffer = buf.readByteArray(len);
            }

            createSocketEvent("socket.native.send", {
                method: "send",
                socket_descriptor: this.sd,
                socket_type: socketState.socketType,
                address_family: socketState.addressFamily,
                protocol: socketState.protocol,
                result_code: len,
                local_ip: local.ip,
                local_port: local.port,
                remote_ip: remote.ip,
                remote_port: remote.port,
                data_length: len,
                has_buffer: buffer !== undefined
            });

            if (buffer) {
                am_send(PROFILE_HOOKING_TYPE, JSON.stringify({
                    event_type: "socket.native.send_data",
                    timestamp: Date.now(),
                    socket_descriptor: this.sd,
                    data_length: len
                }), buffer);
            }
        }
    });

    safeAttachExport("libc.so", "recv", "sockets:recv", {
        onEnter(args) {
            this.sd = args[0].toInt32();
            this.addr = args[1];
            this.buflen = args[2].toInt32();
        },
        onLeave(retval) {
            const len = retval.toInt32();

            if (len <= 0 || len > this.buflen) {
                return;
            }

            const socketState = trackSocketFromRuntime(this.sd);

            if (!socketState || !isInetSocketType(socketState.socketType)) {
                return;
            }

            const socketLocal = Socket.localAddress(this.sd);
            const local = socketLocal && isTcpEndpointAddress(socketLocal)
                ? socketLocal
                : undefined;
            const socketRemote = Socket.peerAddress(this.sd);
            const remote = socketRemote && isTcpEndpointAddress(socketRemote)
                ? socketRemote
                : undefined;

            if (local === undefined || remote === undefined) {
                return;
            }

            let buffer;
            const buf = ptr(this.addr);

            if (!buf.isNull()) {
                buffer = buf.readByteArray(len);
            }

            createSocketEvent("socket.native.recv", {
                method: "recv",
                socket_descriptor: this.sd,
                socket_type: socketState.socketType,
                address_family: socketState.addressFamily,
                protocol: socketState.protocol,
                result_code: len,
                local_ip: local.ip,
                local_port: local.port,
                remote_ip: remote.ip,
                remote_port: remote.port,
                data_length: len,
                has_buffer: buffer !== undefined
            });

            if (buffer) {
                am_send(PROFILE_HOOKING_TYPE, JSON.stringify({
                    event_type: "socket.native.recv_data",
                    timestamp: Date.now(),
                    socket_descriptor: this.sd,
                    data_length: len
                }), buffer);
            }
        }
    });

    safeAttachExport("libc.so", "sendmsg", "sockets:sendmsg", {
        onEnter(args) {
            this.sd = args[0].toInt32();
        },
        onLeave(retval) {
            const len = retval.toInt32();

            if (len === -1) {
                return;
            }

            const socketType = Socket.type(this.sd);
            const socketLocal = Socket.localAddress(this.sd);
            const local = socketLocal && isTcpEndpointAddress(socketLocal)
                ? socketLocal
                : undefined;
            const socketRemote = Socket.peerAddress(this.sd);
            const remote = socketRemote && isTcpEndpointAddress(socketRemote)
                ? socketRemote
                : undefined;

            if (
                socketType === "unix:stream" ||
                socketType == null ||
                local === undefined ||
                remote === undefined
            ) {
                return;
            }

            trackSocketFromRuntime(this.sd);

            const data = {
                event_type: "Libc::sendmsg",
                method: "sendmsg",
                sd: this.sd,
                src_ip: local.ip,
                src_port: local.port,
                dst_ip: remote.ip,
                dst_port: remote.port,
                len: len,
                type: socketType
            };

            am_send(PROFILE_HOOKING_TYPE, JSON.stringify(data));
        }
    });

    safeAttachExport("libc.so", "recvmsg", "sockets:recvmsg", {
        onEnter(args) {
            this.sd = args[0].toInt32();
            this.addr = args[1];
        },
        onLeave(retval) {
            const len = retval.toInt32();

            if (len === -1) {
                return;
            }

            const socketType = Socket.type(this.sd);
            const socketLocal = Socket.localAddress(this.sd);
            const local = socketLocal && isTcpEndpointAddress(socketLocal)
                ? socketLocal
                : undefined;
            const socketRemote = Socket.peerAddress(this.sd);
            const remote = socketRemote && isTcpEndpointAddress(socketRemote)
                ? socketRemote
                : undefined;

            if (
                socketType === "unix:stream" ||
                socketType == null ||
                local === undefined ||
                remote === undefined
            ) {
                return;
            }

            trackSocketFromRuntime(this.sd);

            const data = {
                event_type: "Libc::recvmsg",
                method: "recvmsg",
                sd: this.sd,
                src_ip: remote.ip,
                src_port: remote.port,
                dst_ip: local.ip,
                dst_port: local.port,
                len: len,
                type: socketType
            };

            am_send(PROFILE_HOOKING_TYPE, JSON.stringify(data));
        }
    });

    safeAttachExport("libc.so", "close", "sockets:close", {
        onEnter(args) {
            this.sd = args[0].toInt32();
            this.socketState = nativeSocketStates.get(this.sd);

            if (!this.socketState) {
                return;
            }

            try {
                const socketLocal = Socket.localAddress(this.sd);

                this.local = socketLocal && isTcpEndpointAddress(socketLocal)
                    ? socketLocal
                    : undefined;
            } catch (_) {
                this.local = undefined;
            }

            try {
                const socketRemote = Socket.peerAddress(this.sd);

                this.remote = socketRemote && isTcpEndpointAddress(socketRemote)
                    ? socketRemote
                    : undefined;
            } catch (_) {
                this.remote = undefined;
            }
        },
        onLeave(retval) {
            const resultCode = retval.toInt32();
            const socketState =
                this.socketState as NativeSocketState | undefined;

            if (resultCode !== 0 || !socketState) {
                return;
            }

            const eventData: any = {
                method: "close",
                socket_descriptor: this.sd,
                socket_type: socketState.socketType,
                address_family: socketState.addressFamily,
                protocol: socketState.protocol,
                result_code: resultCode
            };

            if (this.local) {
                eventData.local_ip = this.local.ip;
                eventData.local_port = this.local.port;
            }

            if (this.remote) {
                eventData.remote_ip = this.remote.ip;
                eventData.remote_port = this.remote.port;
            }

            createSocketEvent("socket.native.close", eventData);
            nativeSocketStates.delete(this.sd);
        }
    });
}

export function install_socket_hooks() {
    devlog("\n");
    devlog("install socket hooks");

    try {
        hook_java_socket_communication();
    } catch (error) {
        devlog(`[HOOK] Failed to install Java socket hooks: ${error}`);
    }

    try {
        hook_bionic_socket_communication();
    } catch (error) {
        devlog(`[HOOK] Failed to install bionic socket hooks: ${error}`);
    }
}