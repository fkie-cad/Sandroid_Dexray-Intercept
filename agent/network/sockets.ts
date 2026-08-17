import { devlog, am_send } from "../utils/logging.js"
import { safeDeferred, safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"
import { safeAttachExport } from "../utils/safe_native.js"
import { collectJavaStackTrace } from "../utils/stacktrace.js"


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

// helper functions
function swap16(value) {
    return ((value & 0xFF) << 8) |
        ((value >> 8) & 0xFF);
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

interface NativeSocketEndpoint {
    ip: string;
    port: number;
}

function getSocketEndpoint(
    socketDescriptor: number,
    peer: boolean
): NativeSocketEndpoint | undefined {
    try {
        const address = peer
            ? Socket.peerAddress(socketDescriptor)
            : Socket.localAddress(socketDescriptor);

        return address && isTcpEndpointAddress(address)
            ? {
                ip: address.ip,
                port: address.port
            }
            : undefined;
    } catch (_) {
        return undefined;
    }
}

function getSockaddrLength(addressLengthPointer: any): number | undefined {
    try {
        const pointerValue = ptr(addressLengthPointer);

        if (pointerValue.isNull()) {
            return undefined;
        }

        return pointerValue.readU32();
    } catch (_) {
        return undefined;
    }
}

function getIpv4EndpointFromSockaddr(
    address: any,
    addressLength: number
): NativeSocketEndpoint | undefined {
    if (addressLength < 8) {
        return undefined;
    }

    try {
        const sockaddr = ptr(address);

        if (sockaddr.isNull() || sockaddr.readU16() !== AF_INET) {
            return undefined;
        }

        const port = swap16(sockaddr.add(2).readU16());
        const ip = [
            sockaddr.add(4).readU8(),
            sockaddr.add(5).readU8(),
            sockaddr.add(6).readU8(),
            sockaddr.add(7).readU8()
        ].join(".");

        return {
            ip: ip,
            port: port
        };
    } catch (_) {
        return undefined;
    }
}

function readSocketBuffer(
    address: any,
    length: number
): ArrayBuffer | undefined {
    try {
        const buffer = ptr(address);

        if (buffer.isNull()) {
            return undefined;
        }

        return buffer.readByteArray(length) || undefined;
    } catch (_) {
        return undefined;
    }
}

let nativeSocketOperationCounter = 0;

function createSocketOperationId(socketDescriptor: number): string {
    nativeSocketOperationCounter += 1;

    return `socket-${socketDescriptor}-${nativeSocketOperationCounter}`;
}

function getCapturedLength(
    buffer: ArrayBuffer | undefined
): number | undefined {
    return buffer ? buffer.byteLength : undefined;
}

function sendSocketPayloadEvent(
    eventType: string,
    operationId: string,
    socketDescriptor: number,
    dataLength: number,
    buffer: ArrayBuffer | undefined
): void {
    if (!buffer) {
        return;
    }

    am_send(PROFILE_HOOKING_TYPE, JSON.stringify({
        event_type: eventType,
        timestamp: Date.now(),
        operation_id: operationId,
        socket_descriptor: socketDescriptor,
        data_length: dataLength,
        captured_length: getCapturedLength(buffer),
        has_buffer: true
    }), buffer);
}

const MAX_SOCKET_IOVEC_COUNT = 64;
const MAX_SOCKET_PAYLOAD_CAPTURE = 64 * 1024;

function getNativeSize(address: NativePointer): number | undefined {
    try {
        const rawValue = Process.pointerSize === 8
            ? address.readU64().toString()
            : address.readU32().toString();

        const value = Number(rawValue);

        if (!Number.isSafeInteger(value) || value < 0) {
            return undefined;
        }

        return value;
    } catch (_) {
        return undefined;
    }
}

function captureIovecPayload(
    messageHeaderAddress: any,
    resultLength: number
): ArrayBuffer | undefined {
    if (
        resultLength <= 0 ||
        resultLength > MAX_SOCKET_PAYLOAD_CAPTURE
    ) {
        return undefined;
    }

    try {
        const messageHeader = ptr(messageHeaderAddress);

        if (messageHeader.isNull()) {
            return undefined;
        }

        const pointerSize = Process.pointerSize;

        /*
         * struct msghdr:
         *   void *msg_name;
         *   socklen_t msg_namelen;
         *   struct iovec *msg_iov;
         *   size_t msg_iovlen;
         *
         * The offsets are derived from pointer width and bionic ABI alignment.
         */
        const iovecOffset = pointerSize === 8 ? 16 : 8;
        const iovecCountOffset = pointerSize === 8 ? 24 : 12;
        const iovecStride = pointerSize * 2;

        const iovecAddress = messageHeader
            .add(iovecOffset)
            .readPointer();

        const iovecCount = getNativeSize(
            messageHeader.add(iovecCountOffset)
        );

        if (
            iovecAddress.isNull() ||
            iovecCount === undefined ||
            iovecCount === 0 ||
            iovecCount > MAX_SOCKET_IOVEC_COUNT
        ) {
            return undefined;
        }

        const captured = new Uint8Array(resultLength);
        let remaining = resultLength;
        let destinationOffset = 0;

        for (let index = 0; index < iovecCount && remaining > 0; index++) {
            const iovec = iovecAddress.add(index * iovecStride);
            const bufferAddress = iovec.readPointer();
            const bufferLength = getNativeSize(
                iovec.add(pointerSize)
            );

            if (
                bufferAddress.isNull() ||
                bufferLength === undefined
            ) {
                return undefined;
            }

            const bytesToRead = Math.min(bufferLength, remaining);

            if (bytesToRead === 0) {
                continue;
            }

            const part = bufferAddress.readByteArray(bytesToRead);

            if (!part) {
                return undefined;
            }

            captured.set(
                new Uint8Array(part),
                destinationOffset
            );

            destinationOffset += bytesToRead;
            remaining -= bytesToRead;
        }

        return remaining === 0
            ? captured.buffer
            : undefined;
    } catch (_) {
        return undefined;
    }
}

function getMessageHeaderEndpoint(
    messageHeaderAddress: any
): NativeSocketEndpoint | undefined {
    try {
        const messageHeader = ptr(messageHeaderAddress);

        if (messageHeader.isNull()) {
            return undefined;
        }

        const address = messageHeader.readPointer();
        const addressLength = messageHeader
            .add(Process.pointerSize)
            .readU32();

        if (address.isNull()) {
            return undefined;
        }

        return getIpv4EndpointFromSockaddr(
            address,
            addressLength
        );
    } catch (_) {
        return undefined;
    }
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

                        const java_stack_trace = collectJavaStackTrace();
                        createSocketEvent("socket.java.server_accept", {
                            class: "java.net.ServerSocket",
                            method: "accept",
                            server_info: this.toString(),
                            ...(java_stack_trace ? { java_stack_trace } : {})
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

                        const java_stack_trace = collectJavaStackTrace();
                        createSocketEvent("socket.java.init", {
                            class: "java.net.Socket",
                            method: "$init",
                            host: host,
                            port: port,
                            connection_string: `${host}:${port}`,
                            ...(java_stack_trace ? { java_stack_trace } : {})
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

                        const java_stack_trace = collectJavaStackTrace();
                        createSocketEvent("socket.java.connect", {
                            class: "java.net.Socket",
                            method: "connect",
                            endpoint: endpoint.toString(),
                            timeout: timeout,
                            ...(java_stack_trace ? { java_stack_trace } : {})
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

                        const java_stack_trace = collectJavaStackTrace();
                        createSocketEvent("socket.java.connect", {
                            class: "java.net.Socket",
                            method: "connect",
                            endpoint: endpoint.toString(),
                            ...(java_stack_trace ? { java_stack_trace } : {})
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

                        const java_stack_trace = collectJavaStackTrace();
                        createSocketEvent("socket.java.local_accept", {
                            class: "android.net.LocalServerSocket",
                            method: "accept",
                            server_info: this.toString(),
                            ...(java_stack_trace ? { java_stack_trace } : {})
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

                        const java_stack_trace = collectJavaStackTrace();
                        createSocketEvent("socket.java.datagram_connect", {
                            class: "java.net.DatagramSocket",
                            method: "connect",
                            address: address.toString(),
                            port: port,
                            connection_string: `${address}:${port}`,
                            ...(java_stack_trace ? { java_stack_trace } : {})
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
            const operationId = createSocketOperationId(this.sd);

            createSocketEvent("socket.native.write", {
                method: "write",
                operation_id: operationId,
                socket_descriptor: this.sd,
                socket_type: socketType,
                local_ip: local.ip,
                local_port: local.port,
                remote_ip: remote.ip,
                remote_port: remote.port,
                data_length: len,
                captured_length: getCapturedLength(buffer),
                has_buffer: buffer !== undefined
            });

            sendSocketPayloadEvent(
                "socket.native.write_data",
                operationId,
                this.sd,
                len,
                buffer
            );
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

                const operationId = createSocketOperationId(this.sd);

                createSocketEvent("socket.native.read", {
                    method: "read",
                    operation_id: operationId,
                    socket_descriptor: this.sd,
                    socket_type: socketType,
                    local_ip: local.ip,
                    local_port: local.port,
                    remote_ip: remote.ip,
                    remote_port: remote.port,
                    data_length: len,
                    captured_length: getCapturedLength(buffer),
                    has_buffer: buffer !== undefined
                });

                sendSocketPayloadEvent(
                    "socket.native.read_data",
                    operationId,
                    this.sd,
                    len,
                    buffer
                );
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
            this.destinationAddress = args[4];
            this.destinationAddressLength = args[5].toInt32();
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

            const local = getSocketEndpoint(this.sd, false);
            let remote: NativeSocketEndpoint | undefined;

            if (this.destinationAddress.isNull()) {
                remote = getSocketEndpoint(this.sd, true);
            } else {
                remote = getIpv4EndpointFromSockaddr(
                    this.destinationAddress,
                    this.destinationAddressLength
                );
            }

            const buffer = readSocketBuffer(this.addr, len);
            const operationId = createSocketOperationId(this.sd);

            const eventData: any = {
                method: "sendto",
                operation_id: operationId,
                socket_descriptor: this.sd,
                socket_type: socketState.socketType,
                address_family: socketState.addressFamily,
                protocol: socketState.protocol,
                result_code: len,
                data_length: len,
                captured_length: getCapturedLength(buffer),
                has_buffer: buffer !== undefined
            };

            if (local) {
                eventData.local_ip = local.ip;
                eventData.local_port = local.port;
            }

            if (remote) {
                eventData.remote_ip = remote.ip;
                eventData.remote_port = remote.port;
            }

            createSocketEvent("socket.native.sendto", eventData);

            sendSocketPayloadEvent(
                "socket.native.sendto_data",
                operationId,
                this.sd,
                len,
                buffer
            );
        }
    });

    safeAttachExport("libc.so", "recvfrom", "sockets:recvfrom", {
        onEnter(args) {
            this.sd = args[0].toInt32();
            this.addr = args[1];
            this.buflen = args[2].toInt32();
            this.sourceAddress = args[4];
            this.sourceAddressLengthPointer = args[5];
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

            const local = getSocketEndpoint(this.sd, false);
            let remote: NativeSocketEndpoint | undefined;

            if (this.sourceAddress.isNull()) {
                remote = getSocketEndpoint(this.sd, true);
            } else {
                const sourceAddressLength = getSockaddrLength(
                    this.sourceAddressLengthPointer
                );

                if (sourceAddressLength !== undefined) {
                    remote = getIpv4EndpointFromSockaddr(
                        this.sourceAddress,
                        sourceAddressLength
                    );
                }
            }

            const buffer = readSocketBuffer(this.addr, len);
            const operationId = createSocketOperationId(this.sd);

            const eventData: any = {
                method: "recvfrom",
                operation_id: operationId,
                socket_descriptor: this.sd,
                socket_type: socketState.socketType,
                address_family: socketState.addressFamily,
                protocol: socketState.protocol,
                result_code: len,
                data_length: len,
                captured_length: getCapturedLength(buffer),
                has_buffer: buffer !== undefined
            };

            if (local) {
                eventData.local_ip = local.ip;
                eventData.local_port = local.port;
            }

            if (remote) {
                eventData.remote_ip = remote.ip;
                eventData.remote_port = remote.port;
            }

            createSocketEvent("socket.native.recvfrom", eventData);

            sendSocketPayloadEvent(
                "socket.native.recvfrom_data",
                operationId,
                this.sd,
                len,
                buffer
            );
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
            const operationId = createSocketOperationId(this.sd);

            createSocketEvent("socket.native.send", {
                method: "send",
                operation_id: operationId,
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
                captured_length: getCapturedLength(buffer),
                has_buffer: buffer !== undefined
            });

            sendSocketPayloadEvent(
                "socket.native.send_data",
                operationId,
                this.sd,
                len,
                buffer
            );
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
            const operationId = createSocketOperationId(this.sd);

            createSocketEvent("socket.native.recv", {
                method: "recv",
                operation_id: operationId,
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
                captured_length: getCapturedLength(buffer),
                has_buffer: buffer !== undefined
            });

            sendSocketPayloadEvent(
                "socket.native.recv_data",
                operationId,
                this.sd,
                len,
                buffer
            );
        }
    });

    safeAttachExport("libc.so", "sendmsg", "sockets:sendmsg", {
        onEnter(args) {
            this.sd = args[0].toInt32();
            this.messageHeader = args[1];
        },
        onLeave(retval) {
            const len = retval.toInt32();

            if (len <= 0) {
                return;
            }

            const socketState = trackSocketFromRuntime(this.sd);

            if (!socketState || !isInetSocketType(socketState.socketType)) {
                return;
            }

            const local = getSocketEndpoint(this.sd, false);
            const remote =
                getMessageHeaderEndpoint(this.messageHeader) ||
                getSocketEndpoint(this.sd, true);

            const buffer = captureIovecPayload(
                this.messageHeader,
                len
            );
            const operationId = createSocketOperationId(this.sd);

            const eventData: any = {
                method: "sendmsg",
                operation_id: operationId,
                socket_descriptor: this.sd,
                socket_type: socketState.socketType,
                address_family: socketState.addressFamily,
                protocol: socketState.protocol,
                result_code: len,
                data_length: len,
                captured_length: getCapturedLength(buffer),
                has_buffer: buffer !== undefined
            };

            if (local) {
                eventData.local_ip = local.ip;
                eventData.local_port = local.port;
            }

            if (remote) {
                eventData.remote_ip = remote.ip;
                eventData.remote_port = remote.port;
            }

            createSocketEvent("socket.native.sendmsg", eventData);

            sendSocketPayloadEvent(
                "socket.native.sendmsg_data",
                operationId,
                this.sd,
                len,
                buffer
            );
        }
    });

    safeAttachExport("libc.so", "recvmsg", "sockets:recvmsg", {
        onEnter(args) {
            this.sd = args[0].toInt32();
            this.messageHeader = args[1];
        },
        onLeave(retval) {
            const len = retval.toInt32();

            if (len <= 0) {
                return;
            }

            const socketState = trackSocketFromRuntime(this.sd);

            if (!socketState || !isInetSocketType(socketState.socketType)) {
                return;
            }

            const local = getSocketEndpoint(this.sd, false);
            const remote =
                getMessageHeaderEndpoint(this.messageHeader) ||
                getSocketEndpoint(this.sd, true);

            const buffer = captureIovecPayload(
                this.messageHeader,
                len
            );
            const operationId = createSocketOperationId(this.sd);

            const eventData: any = {
                method: "recvmsg",
                operation_id: operationId,
                socket_descriptor: this.sd,
                socket_type: socketState.socketType,
                address_family: socketState.addressFamily,
                protocol: socketState.protocol,
                result_code: len,
                data_length: len,
                captured_length: getCapturedLength(buffer),
                has_buffer: buffer !== undefined
            };

            if (local) {
                eventData.local_ip = local.ip;
                eventData.local_port = local.port;
            }

            if (remote) {
                eventData.remote_ip = remote.ip;
                eventData.remote_port = remote.port;
            }

            createSocketEvent("socket.native.recvmsg", eventData);

            sendSocketPayloadEvent(
                "socket.native.recvmsg_data",
                operationId,
                this.sd,
                len,
                buffer
            );
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