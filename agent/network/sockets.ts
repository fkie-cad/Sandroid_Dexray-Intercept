import { devlog, am_send } from "../utils/logging.js"
import { Java } from "../utils/javalib.js"
import { PropagateException, safeDeferred, safeImplementation, safeOverload, safePerform, safeUse } from "../utils/safe_java.js"
import { safeAttachExport } from "../utils/safe_native.js"
import { collectJavaStackTrace, collectNativeBacktrace } from "../utils/stacktrace.js"


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
const AF_UNIX = 1;

const SOCK_STREAM = 1;
const SOCK_DGRAM = 2;

interface NativeSocketState {
    socketType: string;
    addressFamily?: number;
    protocol?: number;
    localPath?: string;
    remotePath?: string;
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

    if (addressFamily === AF_UNIX) {
        if (baseType === SOCK_STREAM) return "unix:stream";
        if (baseType === SOCK_DGRAM) return "unix:dgram";
    }

    return null;
}

function isInetSocketType(socketType: string): boolean {
    return socketType === "tcp" ||
        socketType === "tcp6" ||
        socketType === "udp" ||
        socketType === "udp6";
}

function isUnixSocketType(socketType: string): boolean {
    return socketType === "unix:stream" ||
        socketType === "unix:dgram";
}

function isTrackableSocketType(socketType: string): boolean {
    return isInetSocketType(socketType) || isUnixSocketType(socketType);
}

function trackNativeSocket(
    socketDescriptor: number,
    socketType: string,
    addressFamily?: number,
    protocol?: number
): NativeSocketState {
    /*
     * A directly observed, successful socket() call is authoritative: the
     * kernel only hands back a given fd number once its previous holder (if
     * any) has been closed. Any entry already present under this descriptor
     * is therefore guaranteed stale (a prior socket that reused this fd
     * number) and must be discarded rather than reused, otherwise cached
     * fields such as localPath/remotePath (and even socketType itself) can
     * leak across unrelated sockets that happen to share an fd number.
     */
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

        if (!socketType || !isTrackableSocketType(socketType)) {
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
            protocol: listeningState.protocol,
            // Unix accepted sockets share the listener's bound path; the
            // client's own address is not exposed the same way a connect()
            // peer's remote path is, so remotePath is intentionally omitted.
            localPath: listeningState.localPath
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

interface UnixSocketAddress {
    path: string;
    namespace: "abstract" | "filesystem";
}

/*
 * struct sockaddr_un:
 *   sa_family_t sun_family;   // 2 bytes on Linux/Android
 *   char        sun_path[108];
 *
 * A leading NUL byte in sun_path indicates the abstract namespace (a Linux
 * extension also used by Android's LocalSocket abstract addressing): the
 * name is the remaining bytes up to addressLength, and is not itself
 * NUL-terminated. Anything else is a filesystem-namespace path, which is
 * a NUL-terminated string starting at sun_path[0].
 */
function parseSockaddrUn(
    address: any,
    addressLength: number
): UnixSocketAddress | undefined {
    if (addressLength < 3) {
        return undefined;
    }

    try {
        const sockaddr = ptr(address);

        if (sockaddr.isNull() || sockaddr.readU16() !== AF_UNIX) {
            return undefined;
        }

        const pathPointer = sockaddr.add(2);
        const firstByte = pathPointer.readU8();

        if (firstByte === 0) {
            const nameLength = addressLength - 3;

            if (nameLength <= 0) {
                return undefined;
            }

            const nameBytes = pathPointer.add(1).readByteArray(nameLength);

            if (!nameBytes) {
                return undefined;
            }

            const name = Array.from(new Uint8Array(nameBytes))
                .map((byte) => String.fromCharCode(byte))
                .join("");

            return { path: name, namespace: "abstract" };
        }

        const path = pathPointer.readCString();

        if (!path) {
            return undefined;
        }

        return { path, namespace: "filesystem" };
    } catch (_) {
        return undefined;
    }
}

function formatUnixSocketEndpoint(
    address: UnixSocketAddress | undefined
): string | undefined {
    return address ? `${address.namespace}:${address.path}` : undefined;
}

/*
 * Generic endpoint-field lookup shared by the payload-bearing syscall hooks
 * (send/recv/write/read). AF_UNIX sockets carry no per-call address argument
 * for these syscalls, so their endpoints come from state cached at bind()/
 * connect() time rather than a live Frida Socket.* lookup, which returns an
 * empty/useless path for AF_UNIX (see NativeSocketState.localPath/remotePath).
 */
function getNativeSocketEndpointFields(
    socketDescriptor: number,
    socketState: NativeSocketState
): any {
    const fields: any = {};

    if (isUnixSocketType(socketState.socketType)) {
        if (socketState.localPath) {
            fields.local_address = socketState.localPath;
        }

        if (socketState.remotePath) {
            fields.remote_address = socketState.remotePath;
        }

        return fields;
    }

    const socketLocal = Socket.localAddress(socketDescriptor);
    const local = socketLocal && isTcpEndpointAddress(socketLocal)
        ? socketLocal
        : undefined;

    const socketRemote = Socket.peerAddress(socketDescriptor);
    const remote = socketRemote && isTcpEndpointAddress(socketRemote)
        ? socketRemote
        : undefined;

    if (local) {
        fields.local_ip = local.ip;
        fields.local_port = local.port;
    }

    if (remote) {
        fields.remote_ip = remote.ip;
        fields.remote_port = remote.port;
    }

    return fields;
}

interface CapturedSocketPayload {
    buffer: ArrayBuffer | undefined;
    truncated: boolean;
}

function readSocketBufferCapped(
    address: any,
    length: number
): CapturedSocketPayload {
    if (length <= 0) {
        return { buffer: undefined, truncated: false };
    }

    const captureLength = Math.min(length, MAX_SOCKET_PAYLOAD_CAPTURE);

    try {
        const pointer = ptr(address);

        if (pointer.isNull()) {
            return { buffer: undefined, truncated: false };
        }

        const buffer = pointer.readByteArray(captureLength) || undefined;

        return {
            buffer,
            truncated: buffer !== undefined && captureLength < length
        };
    } catch (_) {
        return { buffer: undefined, truncated: false };
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
    buffer: ArrayBuffer | undefined,
    truncated: boolean
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
        has_buffer: true,
        payload_truncated: truncated
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
): CapturedSocketPayload {
    if (resultLength <= 0) {
        return { buffer: undefined, truncated: false };
    }

    const captureLength = Math.min(resultLength, MAX_SOCKET_PAYLOAD_CAPTURE);

    try {
        const messageHeader = ptr(messageHeaderAddress);

        if (messageHeader.isNull()) {
            return { buffer: undefined, truncated: false };
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
            return { buffer: undefined, truncated: false };
        }

        const captured = new Uint8Array(captureLength);
        let remaining = captureLength;
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
                return { buffer: undefined, truncated: false };
            }

            const bytesToRead = Math.min(bufferLength, remaining);

            if (bytesToRead === 0) {
                continue;
            }

            const part = bufferAddress.readByteArray(bytesToRead);

            if (!part) {
                return { buffer: undefined, truncated: false };
            }

            captured.set(
                new Uint8Array(part),
                destinationOffset
            );

            destinationOffset += bytesToRead;
            remaining -= bytesToRead;
        }

        return remaining === 0
            ? {
                buffer: captured.buffer,
                truncated: captureLength < resultLength
            }
            : { buffer: undefined, truncated: false };
    } catch (_) {
        return { buffer: undefined, truncated: false };
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

function getMessageHeaderUnixEndpoint(
    messageHeaderAddress: any
): UnixSocketAddress | undefined {
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

        return parseSockaddrUn(address, addressLength);
    } catch (_) {
        return undefined;
    }
}

function callJavaOriginal(
    original: any,
    receiver: any,
    ...args: any[]
): any {
    try {
        return original.call(receiver, ...args);
    } catch (error) {
        throw new PropagateException(error);
    }
}

function createSocketEventSafely(
    eventType: string,
    data: any
): void {
    try {
        createSocketEvent(eventType, data);
    } catch (error) {
        devlog(`[HOOK] Failed to create ${eventType} event: ${error}`);
    }
}

function getJavaInetAddressString(address: any): string | undefined {
    try {
        if (!address) {
            return undefined;
        }

        const value = address.getHostAddress();

        return value ? value.toString() : undefined;
    } catch (_) {
        return undefined;
    }
}

function getJavaSocketType(address: string | undefined): string {
    return address && address.includes(":") ? "tcp6" : "tcp";
}

function getJavaDatagramSocketType(address: string | undefined): string {
    return address && address.includes(":") ? "udp6" : "udp";
}

function formatSocketAddress(
    address: string | undefined,
    port: number | undefined
): string | undefined {
    if (!address || port === undefined || port === null || port < 0) {
        return undefined;
    }

    return address.includes(":")
        ? `[${address}]:${port}`
        : `${address}:${port}`;
}

function getJavaSocketEndpointData(socket: any): any {
    const data: any = {};

    try {
        const localAddress = getJavaInetAddressString(socket.getLocalAddress());
        const localPort = socket.getLocalPort();

        if (localAddress !== undefined && localPort >= 0) {
            data.local_ip = localAddress;
            data.local_port = localPort;
            data.local_address = formatSocketAddress(
                localAddress,
                localPort
            );
        }
    } catch (_) {
        // Endpoint information is optional.
    }

    try {
        const remoteAddress = getJavaInetAddressString(socket.getInetAddress());
        const remotePort = socket.getPort();

        if (remoteAddress !== undefined && remotePort >= 0) {
            data.remote_ip = remoteAddress;
            data.remote_port = remotePort;
            data.remote_address = formatSocketAddress(
                remoteAddress,
                remotePort
            );
            data.connection_string = data.remote_address;
        }
    } catch (_) {
        // Endpoint information is optional.
    }

    return data;
}

function getJavaDatagramEndpointData(socket: any): any {
    const data: any = {};

    try {
        const localAddress = getJavaInetAddressString(socket.getLocalAddress());
        const localPort = socket.getLocalPort();

        if (localAddress !== undefined && localPort >= 0) {
            data.local_ip = localAddress;
            data.local_port = localPort;
            data.local_address = formatSocketAddress(
                localAddress,
                localPort
            );
        }
    } catch (_) {
        // Endpoint information is optional.
    }

    try {
        const remoteAddress = getJavaInetAddressString(socket.getInetAddress());
        const remotePort = socket.getPort();

        if (remoteAddress !== undefined && remotePort >= 0) {
            data.remote_ip = remoteAddress;
            data.remote_port = remotePort;
            data.remote_address = formatSocketAddress(
                remoteAddress,
                remotePort
            );
            data.connection_string = data.remote_address;
        }
    } catch (_) {
        // Endpoint information is optional.
    }

    return data;
}

function getJavaLocalSocketAddressString(
    address: any
): string | undefined {
    try {
        if (!address) {
            return undefined;
        }

        const name = address.getName();

        if (!name) {
            return undefined;
        }

        const namespace = address.getNamespace();
        const namespaceName = namespace
            ? namespace.toString().toLowerCase()
            : "unknown";

        return `${namespaceName}:${name.toString()}`;
    } catch (_) {
        return undefined;
    }
}

function getJavaLocalServerSocketEndpointData(
    serverSocket: any
): any {
    const data: any = {};

    try {
        const address = serverSocket.getLocalSocketAddress();
        const localAddress = getJavaLocalSocketAddressString(address);

        if (localAddress !== undefined) {
            data.local_address = localAddress;
            data.endpoint = localAddress;
        }
    } catch (_) {
        // LocalServerSocket endpoint information is optional.
    }

    return data;
}

interface SocketOverloadHookConfig {
    classLabel: string;
    methodName: string;
    eventType: string;
    shouldHook?: (argumentTypes: any[]) => boolean;
    getEndpointData: (instance: any) => any;
    getSocketType: (endpointData: any) => string;
    getExtraFields?: (args: any[], argumentTypes: any[]) => any;
}

function buildOverloadSignature(
    methodName: string,
    argumentTypes: any[]
): string {
    const argsList = argumentTypes
        .map((argumentType: any) => argumentType.className)
        .join(",");

    return `${methodName}(${argsList})`;
}

const socketOperationGuardDepth = new Map<string, number>();

function getSocketOperationGuardKey(classLabel: string): string {
    return `${classLabel}:${Process.getCurrentThreadId()}`;
}

function isNestedSocketOperation(groupKey: string): boolean {
    return (socketOperationGuardDepth.get(groupKey) || 0) > 0;
}

function withSocketOperationGuard<T>(groupKey: string, fn: () => T): T {
    const depth = socketOperationGuardDepth.get(groupKey) || 0;
    socketOperationGuardDepth.set(groupKey, depth + 1);

    try {
        return fn();
    } finally {
        if (depth === 0) {
            socketOperationGuardDepth.delete(groupKey);
        } else {
            socketOperationGuardDepth.set(groupKey, depth);
        }
    }
}

function hookSocketOverloads(
    javaClass: any,
    config: SocketOverloadHookConfig
): void {
    const method = javaClass[config.methodName];

    if (!method || !method.overloads) {
        return;
    }

    method.overloads.forEach((overload: any, index: number) => {
        const argumentTypes = overload.argumentTypes;

        if (config.shouldHook && !config.shouldHook(argumentTypes)) {
            return;
        }

        const signature = buildOverloadSignature(
            config.methodName,
            argumentTypes
        );
        const hookContext =
            `sockets:${config.classLabel}.${config.methodName}[${index}]`;

        overload.implementation = safeImplementation(
            hookContext,
            overload,
            function(original: any, ...args: any[]) {
                const groupKey = getSocketOperationGuardKey(
                    config.classLabel
                );
                const alreadyNested = isNestedSocketOperation(groupKey);

                const result = withSocketOperationGuard(groupKey, () =>
                    callJavaOriginal(original, this, ...args)
                );

                if (alreadyNested) {
                    return result;
                }

                const endpointData = config.getEndpointData(this);
                const socketType = config.getSocketType(endpointData);
                const extraFields = config.getExtraFields
                    ? config.getExtraFields(args, argumentTypes)
                    : {};
                const javaStackTrace = collectJavaStackTrace();

                createSocketEventSafely(config.eventType, {
                    class_name: config.classLabel,
                    method: config.methodName,
                    overload_signature: signature,
                    socket_type: socketType,
                    result_code: 0,
                    ...endpointData,
                    ...extraFields,
                    ...(javaStackTrace
                        ? { java_stack_trace: javaStackTrace }
                        : {})
                });

                return result;
            }
        );
    });
}

function getJavaServerSocketEndpointData(serverSocket: any): any {
    const data: any = {};

    try {
        const localAddress = getJavaInetAddressString(
            serverSocket.getInetAddress()
        );
        const localPort = serverSocket.getLocalPort();

        if (localAddress !== undefined && localPort >= 0) {
            data.local_ip = localAddress;
            data.local_port = localPort;
            data.local_address = formatSocketAddress(
                localAddress,
                localPort
            );
            data.endpoint = data.local_address;
        }
    } catch (_) {
        // Endpoint information is optional.
    }

    return data;
}

function isSocketConstructorOverloadSkipped(
    argumentTypes: any[]
): boolean {
    const classNames = argumentTypes.map(
        (argumentType: any) => argumentType.className
    );

    if (
        classNames.length === 3 &&
        classNames[2] === "boolean"
    ) {
        return true; // deprecated stream-mode constructors
    }

    if (
        classNames.length === 1 &&
        classNames[0] === "java.net.SocketImpl"
    ) {
        return true; // protected, not reachable from arbitrary app code
    }

    if (
        classNames.length === 4 &&
        classNames[0] === "[Ljava.net.InetAddress;"
    ) {
        return true; // internal JDK happy-eyeballs helper
    }

    return false;
}

function getSocketConstructorExtraFields(
    args: any[],
    argumentTypes: any[]
): any {
    const classNames = argumentTypes.map(
        (argumentType: any) => argumentType.className
    );
    const extra: any = {};

    if (
        classNames[0] === "java.lang.String" &&
        classNames[1] === "int"
    ) {
        extra.host = args[0];
        extra.port = args[1];
        extra.endpoint = `${args[0]}:${args[1]}`;
    } else if (
        classNames[0] === "java.net.InetAddress" &&
        classNames[1] === "int"
    ) {
        const host = getJavaInetAddressString(args[0]);

        if (host !== undefined) {
            extra.host = host;
            extra.port = args[1];
            extra.endpoint = `${host}:${args[1]}`;
        }
    } else if (
        classNames.length === 1 &&
        classNames[0] === "java.net.Proxy"
    ) {
        try {
            if (args[0]) {
                extra.proxy = args[0].toString();
            }
        } catch (_) {
            // Proxy stringification is optional.
        }
    }

    return extra;
}

function getBindExtraFields(
    args: any[],
    argumentTypes: any[]
): any {
    const extra: any = {};

    if (argumentTypes.length === 2) {
        extra.backlog = args[1];
    }

    return extra;
}

function isDatagramSocketConstructorOverloadSkipped(
    argumentTypes: any[]
): boolean {
    return (
        argumentTypes.length === 1 &&
        argumentTypes[0].className === "java.net.DatagramSocketImpl"
    );
}

function isLocalSocketConstructorOverloadSkipped(
    argumentTypes: any[]
): boolean {
    return (
        argumentTypes.length === 2 &&
        argumentTypes[0].className === "android.net.LocalSocketImpl"
    );
}

function getJavaLocalSocketEndpointData(localSocket: any): any {
    const data: any = {};

    try {
        const address = localSocket.getLocalSocketAddress();
        const localAddress = getJavaLocalSocketAddressString(address);

        if (localAddress !== undefined) {
            data.local_address = localAddress;
            data.endpoint = localAddress;
        }
    } catch (_) {
        // Endpoint information is optional.
    }

    return data;
}

function getLocalSocketBindExtraFields(args: any[]): any {
    const extra: any = {};
    const address = getJavaLocalSocketAddressString(args[0]);

    if (address !== undefined) {
        extra.local_address = address;
        extra.endpoint = address;
    }

    return extra;
}

let cachedInetSocketAddressClass: any = null;

function getInetSocketAddressClass(): any {
    if (!cachedInetSocketAddressClass) {
        cachedInetSocketAddressClass = safeUse(
            "java.net.InetSocketAddress",
            "sockets:getInetSocketAddressClass"
        );
    }

    return cachedInetSocketAddressClass;
}

function getNioSocketAddressEndpoint(
    address: any
): NativeSocketEndpoint | undefined {
    try {
        if (!address) {
            return undefined;
        }

        const InetSocketAddress = getInetSocketAddressClass();

        if (!InetSocketAddress) {
            return undefined;
        }

        const typedAddress = Java.cast(address, InetSocketAddress);
        const ip = getJavaInetAddressString(typedAddress.getAddress());
        const port = typedAddress.getPort();

        if (ip !== undefined && port >= 0) {
            return { ip, port };
        }

        return undefined;
    } catch (_) {
        return undefined;
    }
}

function getNioChannelEndpointData(channel: any): any {
    const data: any = {};

    try {
        const localEndpoint = getNioSocketAddressEndpoint(
            channel.getLocalAddress()
        );

        if (localEndpoint) {
            data.local_ip = localEndpoint.ip;
            data.local_port = localEndpoint.port;
            data.local_address = formatSocketAddress(
                localEndpoint.ip,
                localEndpoint.port
            );
        }
    } catch (_) {
        // Endpoint information is optional.
    }

    try {
        const remoteEndpoint = getNioSocketAddressEndpoint(
            channel.getRemoteAddress()
        );

        if (remoteEndpoint) {
            data.remote_ip = remoteEndpoint.ip;
            data.remote_port = remoteEndpoint.port;
            data.remote_address = formatSocketAddress(
                remoteEndpoint.ip,
                remoteEndpoint.port
            );
            data.connection_string = data.remote_address;
        }
    } catch (_) {
        // Endpoint information is optional.
    }

    return data;
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
        const LocalSocket = safeUse(
            "android.net.LocalSocket",
            "sockets:hook_java_socket_communication"
        );
        const DatagramSocket = safeUse(
            "java.net.DatagramSocket",
            "sockets:hook_java_socket_communication"
        );

        if (ServerSocket) {
            hookSocketOverloads(ServerSocket, {
                classLabel: "java.net.ServerSocket",
                methodName: "$init",
                eventType: "socket.java.server_init",
                shouldHook: (argumentTypes) =>
                    !isSocketConstructorOverloadSkipped(argumentTypes),
                getEndpointData: getJavaServerSocketEndpointData,
                getSocketType: (endpointData) =>
                    getJavaSocketType(endpointData.local_ip)
            });

            hookSocketOverloads(ServerSocket, {
                classLabel: "java.net.ServerSocket",
                methodName: "bind",
                eventType: "socket.java.bind",
                getEndpointData: getJavaServerSocketEndpointData,
                getSocketType: (endpointData) =>
                    getJavaSocketType(endpointData.local_ip),
                getExtraFields: getBindExtraFields
            });

            const accept = safeOverload(
                ServerSocket.accept,
                "sockets:ServerSocket.accept"
            );

            if (accept) {
                accept.implementation = safeImplementation(
                    "sockets:ServerSocket.accept",
                    accept,
                    function(original) {
                        const result = callJavaOriginal(original, this);
                        const endpointData = getJavaSocketEndpointData(result);
                        const javaStackTrace = collectJavaStackTrace();

                        createSocketEventSafely("socket.java.server_accept", {
                            class_name: "java.net.ServerSocket",
                            method: "accept",
                            overload_signature: "accept()",
                            socket_type: getJavaSocketType(
                                endpointData.remote_ip
                            ),
                            server_info: this.toString(),
                            result_code: 0,
                            ...endpointData,
                            ...(javaStackTrace
                                ? { java_stack_trace: javaStackTrace }
                                : {})
                        });

                        return result;
                    }
                );
            }
        }

        if (Socket) {
            hookSocketOverloads(Socket, {
                classLabel: "java.net.Socket",
                methodName: "$init",
                eventType: "socket.java.init",
                shouldHook: (argumentTypes) =>
                    !isSocketConstructorOverloadSkipped(argumentTypes),
                getEndpointData: getJavaSocketEndpointData,
                getSocketType: (endpointData) =>
                    getJavaSocketType(
                        endpointData.remote_ip || endpointData.local_ip
                    ),
                getExtraFields: getSocketConstructorExtraFields
            });

            hookSocketOverloads(Socket, {
                classLabel: "java.net.Socket",
                methodName: "bind",
                eventType: "socket.java.bind",
                getEndpointData: getJavaSocketEndpointData,
                getSocketType: (endpointData) =>
                    getJavaSocketType(
                        endpointData.remote_ip || endpointData.local_ip
                    )
            });

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
                        const result = callJavaOriginal(
                            original,
                            this,
                            endpoint,
                            timeout
                        );
                        const endpointData = getJavaSocketEndpointData(this);
                        const javaStackTrace = collectJavaStackTrace();

                        createSocketEventSafely("socket.java.connect", {
                            class_name: "java.net.Socket",
                            method: "connect",
                            overload_signature:
                                "connect(java.net.SocketAddress,int)",
                            socket_type: getJavaSocketType(
                                endpointData.remote_ip
                            ),
                            endpoint: endpoint.toString(),
                            timeout: timeout,
                            result_code: 0,
                            ...endpointData,
                            ...(javaStackTrace
                                ? { java_stack_trace: javaStackTrace }
                                : {})
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
                        const result = callJavaOriginal(
                            original,
                            this,
                            endpoint
                        );
                        const endpointData = getJavaSocketEndpointData(this);
                        const javaStackTrace = collectJavaStackTrace();

                        createSocketEventSafely("socket.java.connect", {
                            class_name: "java.net.Socket",
                            method: "connect",
                            overload_signature:
                                "connect(java.net.SocketAddress)",
                            socket_type: getJavaSocketType(
                                endpointData.remote_ip
                            ),
                            endpoint: endpoint.toString(),
                            result_code: 0,
                            ...endpointData,
                            ...(javaStackTrace
                                ? { java_stack_trace: javaStackTrace }
                                : {})
                        });

                        return result;
                    }
                );
            }
        }

        if (LocalServerSocket) {
            hookSocketOverloads(LocalServerSocket, {
                classLabel: "android.net.LocalServerSocket",
                methodName: "$init",
                eventType: "socket.java.local_server_init",
                getEndpointData: getJavaLocalServerSocketEndpointData,
                getSocketType: () => "local"
            });

            const localAccept = safeOverload(
                LocalServerSocket.accept,
                "sockets:LocalServerSocket.accept"
            );

            if (localAccept) {
                localAccept.implementation = safeImplementation(
                    "sockets:LocalServerSocket.accept",
                    localAccept,
                    function(original) {
                        const result = callJavaOriginal(original, this);
                        const endpointData =
                            getJavaLocalServerSocketEndpointData(this);
                        const javaStackTrace = collectJavaStackTrace();

                        createSocketEventSafely("socket.java.local_accept", {
                            class_name: "android.net.LocalServerSocket",
                            method: "accept",
                            overload_signature: "accept()",
                            socket_type: "local",
                            server_info: this.toString(),
                            result_code: 0,
                            ...endpointData,
                            ...(javaStackTrace
                                ? { java_stack_trace: javaStackTrace }
                                : {})
                        });

                        return result;
                    }
                );
            }
        }

        if (LocalSocket) {
            hookSocketOverloads(LocalSocket, {
                classLabel: "android.net.LocalSocket",
                methodName: "$init",
                eventType: "socket.java.local_init",
                shouldHook: (argumentTypes) =>
                    !isLocalSocketConstructorOverloadSkipped(argumentTypes),
                getEndpointData: getJavaLocalSocketEndpointData,
                getSocketType: () => "local"
            });

            hookSocketOverloads(LocalSocket, {
                classLabel: "android.net.LocalSocket",
                methodName: "bind",
                eventType: "socket.java.local_bind",
                getEndpointData: getJavaLocalSocketEndpointData,
                getSocketType: () => "local",
                getExtraFields: (args) => getLocalSocketBindExtraFields(args)
            });

            const localConnect = safeOverload(
                LocalSocket.connect,
                "sockets:LocalSocket.connect",
                "android.net.LocalSocketAddress"
            );

            if (localConnect) {
                localConnect.implementation = safeImplementation(
                    "sockets:LocalSocket.connect[LocalSocketAddress]",
                    localConnect,
                    function(original, endpoint) {
                        const result = callJavaOriginal(
                            original,
                            this,
                            endpoint
                        );
                        const remoteAddress =
                            getJavaLocalSocketAddressString(endpoint);
                        const javaStackTrace = collectJavaStackTrace();
                        const endpointData: any = {};

                        if (remoteAddress !== undefined) {
                            endpointData.endpoint = remoteAddress;
                            endpointData.remote_address = remoteAddress;
                            endpointData.connection_string = remoteAddress;
                        }

                        createSocketEventSafely("socket.java.local_connect", {
                            class_name: "android.net.LocalSocket",
                            method: "connect",
                            overload_signature:
                                "connect(android.net.LocalSocketAddress)",
                            socket_type: "local",
                            result_code: 0,
                            ...endpointData,
                            ...(javaStackTrace
                                ? { java_stack_trace: javaStackTrace }
                                : {})
                        });

                        return result;
                    }
                );
            }
        }

        if (DatagramSocket) {
            hookSocketOverloads(DatagramSocket, {
                classLabel: "java.net.DatagramSocket",
                methodName: "$init",
                eventType: "socket.java.datagram_init",
                shouldHook: (argumentTypes) =>
                    !isDatagramSocketConstructorOverloadSkipped(argumentTypes),
                getEndpointData: getJavaDatagramEndpointData,
                getSocketType: (endpointData) =>
                    getJavaDatagramSocketType(
                        endpointData.local_ip || endpointData.remote_ip
                    )
            });

            hookSocketOverloads(DatagramSocket, {
                classLabel: "java.net.DatagramSocket",
                methodName: "bind",
                eventType: "socket.java.bind",
                getEndpointData: getJavaDatagramEndpointData,
                getSocketType: (endpointData) =>
                    getJavaDatagramSocketType(
                        endpointData.local_ip || endpointData.remote_ip
                    )
            });

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
                        const result = callJavaOriginal(
                            original,
                            this,
                            address,
                            port
                        );
                        const endpointData =
                            getJavaDatagramEndpointData(this);
                        const javaStackTrace = collectJavaStackTrace();

                        createSocketEventSafely(
                            "socket.java.datagram_connect",
                            {
                                class_name: "java.net.DatagramSocket",
                                method: "connect",
                                overload_signature:
                                    "connect(java.net.InetAddress,int)",
                                socket_type: getJavaDatagramSocketType(
                                    endpointData.remote_ip
                                ),
                                host: getJavaInetAddressString(address),
                                port: port,
                                endpoint: `${address}:${port}`,
                                result_code: 0,
                                ...endpointData,
                                ...(javaStackTrace
                                    ? {
                                        java_stack_trace: javaStackTrace
                                    }
                                    : {})
                            }
                        );

                        return result;
                    }
                );
            }
        }
    });
}

function hook_nio_socket_channel_communication() {
    safePerform("sockets:hook_nio_socket_channel_communication", () => {
        const SocketChannel = safeUse(
            "java.nio.channels.SocketChannel",
            "sockets:hook_nio_socket_channel_communication"
        );
        const ServerSocketChannel = safeUse(
            "java.nio.channels.ServerSocketChannel",
            "sockets:hook_nio_socket_channel_communication"
        );
        const SocketChannelImpl = safeUse(
            "sun.nio.ch.SocketChannelImpl",
            "sockets:hook_nio_socket_channel_communication"
        );
        const ServerSocketChannelImpl = safeUse(
            "sun.nio.ch.ServerSocketChannelImpl",
            "sockets:hook_nio_socket_channel_communication"
        );

        if (SocketChannel) {
            const openOverload = safeOverload(
                SocketChannel.open,
                "sockets:SocketChannel.open"
            );

            if (openOverload) {
                openOverload.implementation = safeImplementation(
                    "sockets:SocketChannel.open",
                    openOverload,
                    function(original) {
                        const result = callJavaOriginal(original, this);
                        const javaStackTrace = collectJavaStackTrace();

                        createSocketEventSafely("socket.java.channel_open", {
                            class_name: "java.nio.channels.SocketChannel",
                            method: "open",
                            overload_signature: "open()",
                            socket_type: getJavaSocketType(undefined),
                            result_code: 0,
                            ...(javaStackTrace
                                ? { java_stack_trace: javaStackTrace }
                                : {})
                        });

                        return result;
                    }
                );
            }
        }

        if (ServerSocketChannel) {
            const serverOpenOverload = safeOverload(
                ServerSocketChannel.open,
                "sockets:ServerSocketChannel.open"
            );

            if (serverOpenOverload) {
                serverOpenOverload.implementation = safeImplementation(
                    "sockets:ServerSocketChannel.open",
                    serverOpenOverload,
                    function(original) {
                        const result = callJavaOriginal(original, this);
                        const javaStackTrace = collectJavaStackTrace();

                        createSocketEventSafely(
                            "socket.java.channel_server_open",
                            {
                                class_name:
                                    "java.nio.channels.ServerSocketChannel",
                                method: "open",
                                overload_signature: "open()",
                                socket_type: getJavaSocketType(undefined),
                                result_code: 0,
                                ...(javaStackTrace
                                    ? { java_stack_trace: javaStackTrace }
                                    : {})
                            }
                        );

                        return result;
                    }
                );
            }
        }

        if (SocketChannelImpl) {
            hookSocketOverloads(SocketChannelImpl, {
                classLabel: "java.nio.channels.SocketChannel",
                methodName: "bind",
                eventType: "socket.java.channel_bind",
                getEndpointData: getNioChannelEndpointData,
                getSocketType: (endpointData) =>
                    getJavaSocketType(endpointData.local_ip)
            });

            const connectOverload = safeOverload(
                SocketChannelImpl.connect,
                "sockets:SocketChannelImpl.connect",
                "java.net.SocketAddress"
            );

            if (connectOverload) {
                connectOverload.implementation = safeImplementation(
                    "sockets:SocketChannelImpl.connect",
                    connectOverload,
                    function(original, endpoint) {
                        const result = callJavaOriginal(
                            original,
                            this,
                            endpoint
                        );
                        const endpointData = getNioChannelEndpointData(this);
                        const socketType = getJavaSocketType(
                            endpointData.remote_ip || endpointData.local_ip
                        );
                        const javaStackTrace = collectJavaStackTrace();

                        createSocketEventSafely(
                            "socket.java.channel_connect",
                            {
                                class_name:
                                    "java.nio.channels.SocketChannel",
                                method: "connect",
                                overload_signature:
                                    "connect(java.net.SocketAddress)",
                                socket_type: socketType,
                                result_code: result ? 1 : 0,
                                ...endpointData,
                                ...(javaStackTrace
                                    ? { java_stack_trace: javaStackTrace }
                                    : {})
                            }
                        );

                        return result;
                    }
                );
            }

            const finishConnectOverload = safeOverload(
                SocketChannelImpl.finishConnect,
                "sockets:SocketChannelImpl.finishConnect"
            );

            if (finishConnectOverload) {
                finishConnectOverload.implementation = safeImplementation(
                    "sockets:SocketChannelImpl.finishConnect",
                    finishConnectOverload,
                    function(original) {
                        const result = callJavaOriginal(original, this);

                        if (!result) {
                            return result;
                        }

                        const endpointData = getNioChannelEndpointData(this);
                        const socketType = getJavaSocketType(
                            endpointData.remote_ip || endpointData.local_ip
                        );
                        const javaStackTrace = collectJavaStackTrace();

                        createSocketEventSafely(
                            "socket.java.channel_finish_connect",
                            {
                                class_name:
                                    "java.nio.channels.SocketChannel",
                                method: "finishConnect",
                                overload_signature: "finishConnect()",
                                socket_type: socketType,
                                result_code: 1,
                                ...endpointData,
                                ...(javaStackTrace
                                    ? { java_stack_trace: javaStackTrace }
                                    : {})
                            }
                        );

                        return result;
                    }
                );
            }
        }

        if (ServerSocketChannelImpl) {
            hookSocketOverloads(ServerSocketChannelImpl, {
                classLabel: "java.nio.channels.ServerSocketChannel",
                methodName: "bind",
                eventType: "socket.java.channel_bind",
                getEndpointData: getNioChannelEndpointData,
                getSocketType: (endpointData) =>
                    getJavaSocketType(endpointData.local_ip)
            });

            const acceptOverload = safeOverload(
                ServerSocketChannelImpl.accept,
                "sockets:ServerSocketChannelImpl.accept"
            );

            if (acceptOverload) {
                acceptOverload.implementation = safeImplementation(
                    "sockets:ServerSocketChannelImpl.accept",
                    acceptOverload,
                    function(original) {
                        const result = callJavaOriginal(original, this);

                        if (result) {
                            const endpointData =
                                getNioChannelEndpointData(result);
                            const socketType = getJavaSocketType(
                                endpointData.local_ip
                            );
                            const javaStackTrace = collectJavaStackTrace();

                            createSocketEventSafely(
                                "socket.java.channel_accept",
                                {
                                    class_name:
                                        "java.nio.channels.ServerSocketChannel",
                                    method: "accept",
                                    overload_signature: "accept()",
                                    socket_type: socketType,
                                    result_code: 0,
                                    ...endpointData,
                                    ...(javaStackTrace
                                        ? {
                                            java_stack_trace: javaStackTrace
                                        }
                                        : {})
                                }
                            );
                        }

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

            if (!socketState || !isTrackableSocketType(socketState.socketType)) {
                return;
            }

            const socketType = socketState.socketType;
            const eventData: any = {
                method: "bind",
                socket_descriptor: this.sd,
                socket_type: socketType,
                address_family: socketState.addressFamily,
                protocol: socketState.protocol,
                result_code: 0
            };

            if (isUnixSocketType(socketType)) {
                const unixAddress = parseSockaddrUn(this.addr, this.addrlen);

                if (!unixAddress) {
                    return;
                }

                const formatted = formatUnixSocketEndpoint(unixAddress);
                socketState.localPath = formatted;
                eventData.local_address = formatted;
            } else {
                const socketLocal = Socket.localAddress(this.sd);

                if (!isTcpEndpointAddress(socketLocal)) {
                    return;
                }

                eventData.local_ip = socketLocal.ip;
                eventData.local_port = socketLocal.port;
            }

            createSocketEvent("socket.native.bind", eventData);
        }
    });

    safeAttachExport("libc.so", "connect", "sockets:connect", {
        onEnter(args) {
            this.sd = args[0].toInt32();
            this.addr = args[1];
            this.addrlen = args[2].toInt32();
        },
        onLeave(retval) {
            const resultCode = retval.toInt32();

            if (resultCode !== 0) {
                return;
            }

            const socketState = trackSocketFromRuntime(this.sd);

            if (!socketState || !isTrackableSocketType(socketState.socketType)) {
                return;
            }

            const socketType = socketState.socketType;
            const eventData: any = {
                method: "connect",
                socket_descriptor: this.sd,
                socket_type: socketType,
                address_family: socketState.addressFamily,
                protocol: socketState.protocol,
                result_code: resultCode
            };

            if (isUnixSocketType(socketType)) {
                const unixAddress = parseSockaddrUn(this.addr, this.addrlen);

                if (!unixAddress) {
                    return;
                }

                const formatted = formatUnixSocketEndpoint(unixAddress);
                socketState.remotePath = formatted;
                eventData.remote_address = formatted;
            } else {
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

                eventData.local_ip = local.ip;
                eventData.local_port = local.port;
                eventData.remote_ip = remote.ip;
                eventData.remote_port = remote.port;
            }

            createSocketEvent("socket.native.connect", eventData);
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

            const socketState = trackSocketFromRuntime(this.sd);

            if (!socketState || !isTrackableSocketType(socketState.socketType)) {
                return;
            }

            const endpointFields = getNativeSocketEndpointFields(
                this.sd,
                socketState
            );

            if (
                !isUnixSocketType(socketState.socketType) &&
                (endpointFields.local_ip === undefined ||
                    endpointFields.remote_ip === undefined)
            ) {
                return;
            }

            const { buffer, truncated } = readSocketBufferCapped(
                this.addr,
                len
            );
            const operationId = createSocketOperationId(this.sd);
            const native_backtrace = collectNativeBacktrace(this.context);

            createSocketEvent("socket.native.write", {
                method: "write",
                operation_id: operationId,
                socket_descriptor: this.sd,
                socket_type: socketState.socketType,
                address_family: socketState.addressFamily,
                protocol: socketState.protocol,
                result_code: len,
                ...endpointFields,
                data_length: len,
                captured_length: getCapturedLength(buffer),
                has_buffer: buffer !== undefined,
                payload_truncated: truncated,
                ...(native_backtrace ? { native_backtrace } : {})
            });

            sendSocketPayloadEvent(
                "socket.native.write_data",
                operationId,
                this.sd,
                len,
                buffer,
                truncated
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

                const socketState = trackSocketFromRuntime(this.sd);

                if (!socketState || !isTrackableSocketType(socketState.socketType)) {
                    return;
                }

                const endpointFields = getNativeSocketEndpointFields(
                    this.sd,
                    socketState
                );

                if (
                    !isUnixSocketType(socketState.socketType) &&
                    (endpointFields.local_ip === undefined ||
                        endpointFields.remote_ip === undefined)
                ) {
                    return;
                }

                const { buffer, truncated } = readSocketBufferCapped(
                    this.addr,
                    len
                );

                const operationId = createSocketOperationId(this.sd);
                const native_backtrace = collectNativeBacktrace(this.context);

                createSocketEvent("socket.native.read", {
                    method: "read",
                    operation_id: operationId,
                    socket_descriptor: this.sd,
                    socket_type: socketState.socketType,
                    address_family: socketState.addressFamily,
                    protocol: socketState.protocol,
                    result_code: len,
                    ...endpointFields,
                    data_length: len,
                    captured_length: getCapturedLength(buffer),
                    has_buffer: buffer !== undefined,
                    payload_truncated: truncated,
                    ...(native_backtrace ? { native_backtrace } : {})
                });

                sendSocketPayloadEvent(
                    "socket.native.read_data",
                    operationId,
                    this.sd,
                    len,
                    buffer,
                    truncated
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

            if (!socketState || !isTrackableSocketType(socketState.socketType)) {
                return;
            }

            const isUnix = isUnixSocketType(socketState.socketType);
            const eventData: any = {
                method: "sendto",
                operation_id: createSocketOperationId(this.sd),
                socket_descriptor: this.sd,
                socket_type: socketState.socketType,
                address_family: socketState.addressFamily,
                protocol: socketState.protocol,
                result_code: len,
                data_length: len
            };

            if (isUnix) {
                if (socketState.localPath) {
                    eventData.local_address = socketState.localPath;
                }

                if (!this.destinationAddress.isNull()) {
                    const unixDestination = parseSockaddrUn(
                        this.destinationAddress,
                        this.destinationAddressLength
                    );

                    if (unixDestination) {
                        eventData.remote_address =
                            formatUnixSocketEndpoint(unixDestination);
                    }
                } else if (socketState.remotePath) {
                    eventData.remote_address = socketState.remotePath;
                }
            } else {
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

                if (local) {
                    eventData.local_ip = local.ip;
                    eventData.local_port = local.port;
                }

                if (remote) {
                    eventData.remote_ip = remote.ip;
                    eventData.remote_port = remote.port;
                }
            }

            const { buffer, truncated } = readSocketBufferCapped(
                this.addr,
                len
            );
            const native_backtrace = collectNativeBacktrace(this.context);

            eventData.captured_length = getCapturedLength(buffer);
            eventData.has_buffer = buffer !== undefined;
            eventData.payload_truncated = truncated;

            if (native_backtrace) {
                eventData.native_backtrace = native_backtrace;
            }

            createSocketEvent("socket.native.sendto", eventData);

            sendSocketPayloadEvent(
                "socket.native.sendto_data",
                eventData.operation_id,
                this.sd,
                len,
                buffer,
                truncated
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

            if (!socketState || !isTrackableSocketType(socketState.socketType)) {
                return;
            }

            const isUnix = isUnixSocketType(socketState.socketType);
            const eventData: any = {
                method: "recvfrom",
                operation_id: createSocketOperationId(this.sd),
                socket_descriptor: this.sd,
                socket_type: socketState.socketType,
                address_family: socketState.addressFamily,
                protocol: socketState.protocol,
                result_code: len,
                data_length: len
            };

            if (isUnix) {
                if (socketState.localPath) {
                    eventData.local_address = socketState.localPath;
                }

                if (!this.sourceAddress.isNull()) {
                    const sourceAddressLength = getSockaddrLength(
                        this.sourceAddressLengthPointer
                    );

                    if (sourceAddressLength !== undefined) {
                        const unixSource = parseSockaddrUn(
                            this.sourceAddress,
                            sourceAddressLength
                        );

                        if (unixSource) {
                            eventData.remote_address =
                                formatUnixSocketEndpoint(unixSource);
                        }
                    }
                } else if (socketState.remotePath) {
                    eventData.remote_address = socketState.remotePath;
                }
            } else {
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

                if (local) {
                    eventData.local_ip = local.ip;
                    eventData.local_port = local.port;
                }

                if (remote) {
                    eventData.remote_ip = remote.ip;
                    eventData.remote_port = remote.port;
                }
            }

            const { buffer, truncated } = readSocketBufferCapped(
                this.addr,
                len
            );
            const native_backtrace = collectNativeBacktrace(this.context);

            eventData.captured_length = getCapturedLength(buffer);
            eventData.has_buffer = buffer !== undefined;
            eventData.payload_truncated = truncated;

            if (native_backtrace) {
                eventData.native_backtrace = native_backtrace;
            }

            createSocketEvent("socket.native.recvfrom", eventData);

            sendSocketPayloadEvent(
                "socket.native.recvfrom_data",
                eventData.operation_id,
                this.sd,
                len,
                buffer,
                truncated
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

            if (!socketState || !isTrackableSocketType(socketState.socketType)) {
                return;
            }

            const endpointFields = getNativeSocketEndpointFields(
                this.sd,
                socketState
            );

            if (
                !isUnixSocketType(socketState.socketType) &&
                (endpointFields.local_ip === undefined ||
                    endpointFields.remote_ip === undefined)
            ) {
                return;
            }

            const { buffer, truncated } = readSocketBufferCapped(
                this.addr,
                len
            );
            const operationId = createSocketOperationId(this.sd);
            const native_backtrace = collectNativeBacktrace(this.context);

            createSocketEvent("socket.native.send", {
                method: "send",
                operation_id: operationId,
                socket_descriptor: this.sd,
                socket_type: socketState.socketType,
                address_family: socketState.addressFamily,
                protocol: socketState.protocol,
                result_code: len,
                ...endpointFields,
                data_length: len,
                captured_length: getCapturedLength(buffer),
                has_buffer: buffer !== undefined,
                payload_truncated: truncated,
                ...(native_backtrace ? { native_backtrace } : {})
            });

            sendSocketPayloadEvent(
                "socket.native.send_data",
                operationId,
                this.sd,
                len,
                buffer,
                truncated
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

            if (!socketState || !isTrackableSocketType(socketState.socketType)) {
                return;
            }

            const endpointFields = getNativeSocketEndpointFields(
                this.sd,
                socketState
            );

            if (
                !isUnixSocketType(socketState.socketType) &&
                (endpointFields.local_ip === undefined ||
                    endpointFields.remote_ip === undefined)
            ) {
                return;
            }

            const { buffer, truncated } = readSocketBufferCapped(
                this.addr,
                len
            );
            const operationId = createSocketOperationId(this.sd);
            const native_backtrace = collectNativeBacktrace(this.context);

            createSocketEvent("socket.native.recv", {
                method: "recv",
                operation_id: operationId,
                socket_descriptor: this.sd,
                socket_type: socketState.socketType,
                address_family: socketState.addressFamily,
                protocol: socketState.protocol,
                result_code: len,
                ...endpointFields,
                data_length: len,
                captured_length: getCapturedLength(buffer),
                has_buffer: buffer !== undefined,
                payload_truncated: truncated,
                ...(native_backtrace ? { native_backtrace } : {})
            });

            sendSocketPayloadEvent(
                "socket.native.recv_data",
                operationId,
                this.sd,
                len,
                buffer,
                truncated
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

            if (!socketState || !isTrackableSocketType(socketState.socketType)) {
                return;
            }

            const isUnix = isUnixSocketType(socketState.socketType);
            const eventData: any = {
                method: "sendmsg",
                operation_id: createSocketOperationId(this.sd),
                socket_descriptor: this.sd,
                socket_type: socketState.socketType,
                address_family: socketState.addressFamily,
                protocol: socketState.protocol,
                result_code: len,
                data_length: len
            };

            if (isUnix) {
                if (socketState.localPath) {
                    eventData.local_address = socketState.localPath;
                }

                const unixDestination = getMessageHeaderUnixEndpoint(
                    this.messageHeader
                );

                if (unixDestination) {
                    eventData.remote_address =
                        formatUnixSocketEndpoint(unixDestination);
                } else if (socketState.remotePath) {
                    eventData.remote_address = socketState.remotePath;
                }
            } else {
                const local = getSocketEndpoint(this.sd, false);
                const remote =
                    getMessageHeaderEndpoint(this.messageHeader) ||
                    getSocketEndpoint(this.sd, true);

                if (local) {
                    eventData.local_ip = local.ip;
                    eventData.local_port = local.port;
                }

                if (remote) {
                    eventData.remote_ip = remote.ip;
                    eventData.remote_port = remote.port;
                }
            }

            const { buffer, truncated } = captureIovecPayload(
                this.messageHeader,
                len
            );
            const native_backtrace = collectNativeBacktrace(this.context);

            eventData.captured_length = getCapturedLength(buffer);
            eventData.has_buffer = buffer !== undefined;
            eventData.payload_truncated = truncated;

            if (native_backtrace) {
                eventData.native_backtrace = native_backtrace;
            }

            createSocketEvent("socket.native.sendmsg", eventData);

            sendSocketPayloadEvent(
                "socket.native.sendmsg_data",
                eventData.operation_id,
                this.sd,
                len,
                buffer,
                truncated
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

            if (!socketState || !isTrackableSocketType(socketState.socketType)) {
                return;
            }

            const isUnix = isUnixSocketType(socketState.socketType);
            const eventData: any = {
                method: "recvmsg",
                operation_id: createSocketOperationId(this.sd),
                socket_descriptor: this.sd,
                socket_type: socketState.socketType,
                address_family: socketState.addressFamily,
                protocol: socketState.protocol,
                result_code: len,
                data_length: len
            };

            if (isUnix) {
                if (socketState.localPath) {
                    eventData.local_address = socketState.localPath;
                }

                const unixSource = getMessageHeaderUnixEndpoint(
                    this.messageHeader
                );

                if (unixSource) {
                    eventData.remote_address =
                        formatUnixSocketEndpoint(unixSource);
                } else if (socketState.remotePath) {
                    eventData.remote_address = socketState.remotePath;
                }
            } else {
                const local = getSocketEndpoint(this.sd, false);
                const remote =
                    getMessageHeaderEndpoint(this.messageHeader) ||
                    getSocketEndpoint(this.sd, true);

                if (local) {
                    eventData.local_ip = local.ip;
                    eventData.local_port = local.port;
                }

                if (remote) {
                    eventData.remote_ip = remote.ip;
                    eventData.remote_port = remote.port;
                }
            }

            const { buffer, truncated } = captureIovecPayload(
                this.messageHeader,
                len
            );
            const native_backtrace = collectNativeBacktrace(this.context);

            eventData.captured_length = getCapturedLength(buffer);
            eventData.has_buffer = buffer !== undefined;
            eventData.payload_truncated = truncated;

            if (native_backtrace) {
                eventData.native_backtrace = native_backtrace;
            }

            createSocketEvent("socket.native.recvmsg", eventData);

            sendSocketPayloadEvent(
                "socket.native.recvmsg_data",
                eventData.operation_id,
                this.sd,
                len,
                buffer,
                truncated
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

            if (isUnixSocketType(this.socketState.socketType)) {
                this.local = undefined;
                this.remote = undefined;
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

            if (isUnixSocketType(socketState.socketType)) {
                if (socketState.localPath) {
                    eventData.local_address = socketState.localPath;
                }

                if (socketState.remotePath) {
                    eventData.remote_address = socketState.remotePath;
                }
            } else {
                if (this.local) {
                    eventData.local_ip = this.local.ip;
                    eventData.local_port = this.local.port;
                }

                if (this.remote) {
                    eventData.remote_ip = this.remote.ip;
                    eventData.remote_port = this.remote.port;
                }
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
        hook_nio_socket_channel_communication();
    } catch (error) {
        devlog(`[HOOK] Failed to install NIO socket channel hooks: ${error}`);
    }

    try {
        hook_bionic_socket_communication();
    } catch (error) {
        devlog(`[HOOK] Failed to install bionic socket hooks: ${error}`);
    }
}