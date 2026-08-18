import { devlog, am_send } from "../utils/logging.js"
import { Java } from "../utils/javalib.js"
import {
    PropagateException,
    safePerform,
    safeUse,
    safeUseFromClassLoader,
    safeOverload,
    safeImplementation
} from "../utils/safe_java.js"
import { collectJavaStackTrace } from "../utils/stacktrace.js"

const PROFILE_HOOKING_TYPE: string = "WEB"

interface WebEvent {
    event_type: string;
    timestamp: number;
    url?: string;
    method?: string;
    headers?: Record<string, any> | string;
    body?: string;
    java_stack_trace?: string[];
    class?: string;
    uri?: string;
    req_method?: string;
    status_code?: number;
    data?: string;
    mime_type?: string;
    encoding?: string;
    provider_class?: string;
    declaring_class?: string;
    overload_signature?: string;
}

function createWebEvent(eventType: string, data: Partial<WebEvent>): void {
    const event: WebEvent = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

type ConnectionEventPrefix = "http" | "https";

interface RuntimeMethodHookTarget {
    methodName: string;
    parameterTypes: string[];
    overloadSignature: string;
}

const connectionHookRegistry = new Set<string>();

const connectionHookTargets: RuntimeMethodHookTarget[] = [
    {
        methodName: "setRequestMethod",
        parameterTypes: ["java.lang.String"],
        overloadSignature: "setRequestMethod(java.lang.String)"
    },
    {
        methodName: "setRequestProperty",
        parameterTypes: ["java.lang.String", "java.lang.String"],
        overloadSignature: "setRequestProperty(java.lang.String,java.lang.String)"
    },
    {
        methodName: "connect",
        parameterTypes: [],
        overloadSignature: "connect()"
    },
    {
        methodName: "getInputStream",
        parameterTypes: [],
        overloadSignature: "getInputStream()"
    },
    {
        methodName: "getOutputStream",
        parameterTypes: [],
        overloadSignature: "getOutputStream()"
    },
    {
        methodName: "getResponseCode",
        parameterTypes: [],
        overloadSignature: "getResponseCode()"
    }
];

function callOriginal(
    original: any,
    receiver: any,
    ...args: any[]
): any {
    try {
        return original.call(receiver, ...args);
    } catch (error) {
        // Preserve original Java exceptions without calling the method twice.
        throw new PropagateException(error);
    }
}

function createWebEventSafely(
    eventType: string,
    data: Partial<WebEvent>
): void {
    try {
        createWebEvent(eventType, data);
    } catch (error) {
        devlog(`[HOOK] Failed to create ${eventType} event: ${error}`);
    }
}

function getJavaClassName(javaClass: any): string {
    try {
        return javaClass.getName().toString();
    } catch (_) {
        return "unknown";
    }
}

function getRuntimeJavaClass(instance: any): any | null {
    try {
        const Object = safeUse(
            "java.lang.Object",
            "web:getRuntimeJavaClass"
        );
        if (!Object) {
            return null;
        }

        return Java.cast(instance, Object).getClass();
    } catch (error) {
        devlog(`[HOOK] Failed to get runtime Java class: ${error}`);
        return null;
    }
}

function getRuntimeProviderClass(instance: any): string {
    const javaClass = getRuntimeJavaClass(instance);
    return javaClass ? getJavaClassName(javaClass) : "unknown";
}

function getConnectionUrl(connection: any): string {
    try {
        return connection.getURL().toString();
    } catch (_) {
        return "unknown";
    }
}

function getConnectionMethod(connection: any): string {
    try {
        const method = connection.getRequestMethod();
        return method ? method.toString() : "GET";
    } catch (_) {
        return "GET";
    }
}

function getConnectionEventPrefixFromClass(
    javaClass: any
): ConnectionEventPrefix | null {
    try {
        let currentClass = javaClass;

        while (currentClass) {
            const className = getJavaClassName(currentClass);

            if (className === "javax.net.ssl.HttpsURLConnection") {
                return "https";
            }

            if (className === "java.net.HttpURLConnection") {
                return "http";
            }

            currentClass = currentClass.getSuperclass();
        }
    } catch (_) {
        return null;
    }

    return null;
}

function getConnectionEventPrefix(
    connection: any
): ConnectionEventPrefix | null {
    const javaClass = getRuntimeJavaClass(connection);

    if (!javaClass) {
        return null;
    }

    return getConnectionEventPrefixFromClass(javaClass);
}

const connectionEventPrefixStack = new Map<number, ConnectionEventPrefix[]>();

function getConnectionThreadId(): number {
    try {
        return Process.getCurrentThreadId();
    } catch (_) {
        return -1;
    }
}

function getActiveConnectionEventPrefixes(): ConnectionEventPrefix[] {
    const threadId = getConnectionThreadId();

    if (threadId === -1) {
        return [];
    }

    return connectionEventPrefixStack.get(threadId) || [];
}

function hasActiveHttpsConnection(): boolean {
    return getActiveConnectionEventPrefixes().includes("https");
}

function runWithConnectionEventPrefix(
    eventPrefix: ConnectionEventPrefix | null,
    callback: () => any
): any {
    if (!eventPrefix) {
        return callback();
    }

    const threadId = getConnectionThreadId();

    if (threadId === -1) {
        return callback();
    }

    let prefixes = connectionEventPrefixStack.get(threadId);

    if (!prefixes) {
        prefixes = [];
        connectionEventPrefixStack.set(threadId, prefixes);
    }

    prefixes.push(eventPrefix);

    try {
        return callback();
    } finally {
        prefixes.pop();

        if (prefixes.length === 0) {
            connectionEventPrefixStack.delete(threadId);
        }
    }
}

function shouldSuppressConnectionEvent(
    eventPrefix: ConnectionEventPrefix | null
): boolean {
    /*
     * HTTPS providers commonly delegate to an internal HTTP connection.
     * The outer HTTPS operation is the canonical event. Suppress the
     * nested HTTP implementation event, not the underlying method call.
     */
    return eventPrefix === "http" && hasActiveHttpsConnection();
}

function getClassLoaderIdentity(javaClass: any): string {
    try {
        const classLoader = javaClass.getClassLoader();

        if (classLoader === null || classLoader === undefined) {
            return "bootstrap";
        }

        const handle = (classLoader as any).$h;
        return handle ? handle.toString() : classLoader.toString();
    } catch (_) {
        return "unknown";
    }
}

function classDeclaresMethod(
    javaClass: any,
    target: RuntimeMethodHookTarget
): boolean {
    try {
        const methods = javaClass.getDeclaredMethods();

        for (let i = 0; i < methods.length; i++) {
            const method = methods[i];

            if (method.getName().toString() !== target.methodName) {
                continue;
            }

            const modifiers = method.getModifiers();

            // Ignore static and abstract declarations.
            if ((modifiers & 0x0008) !== 0 || (modifiers & 0x0400) !== 0) {
                continue;
            }

            const parameterTypes = method.getParameterTypes();

            if (parameterTypes.length !== target.parameterTypes.length) {
                continue;
            }

            let matches = true;

            for (let j = 0; j < parameterTypes.length; j++) {
                if (parameterTypes[j].getName().toString() !== target.parameterTypes[j]) {
                    matches = false;
                    break;
                }
            }

            if (matches) {
                return true;
            }
        }
    } catch (error) {
        devlog(
            `[HOOK] Failed to inspect ${getJavaClassName(javaClass)} ` +
            `${target.overloadSignature}: ${error}`
        );
    }

    return false;
}

function getConnectionEventMetadata(
    connection: any,
    declaringClassName: string,
    overloadSignature: string
): Partial<WebEvent> {
    return {
        provider_class: getRuntimeProviderClass(connection),
        declaring_class: declaringClassName,
        overload_signature: overloadSignature
    };
}

function installConnectionMethodHook(
    declaringClass: any,
    target: RuntimeMethodHookTarget
): void {
    const declaringClassName = getJavaClassName(declaringClass);
    const classLoaderIdentity = getClassLoaderIdentity(declaringClass);

    const registryKey = [
        classLoaderIdentity,
        declaringClassName,
        target.overloadSignature
    ].join("|");

    if (connectionHookRegistry.has(registryKey)) {
        return;
    }

    // Avoid repeated resolution attempts for the same concrete declaration.
    connectionHookRegistry.add(registryKey);

    const context = `web:${declaringClassName}.${target.overloadSignature}`;

    let classLoader: any = null;

    try {
        classLoader = declaringClass.getClassLoader();
    } catch (_) {
        classLoader = null;
    }

    const Connection = safeUseFromClassLoader(
        declaringClassName,
        classLoader,
        context
    );
    if (!Connection) {
        return;
    }

    const methodRef = Connection[target.methodName];
    const overload = safeOverload(
        methodRef,
        context,
        ...target.parameterTypes
    );
    if (!overload) {
        return;
    }

    overload.implementation = safeImplementation(
        context,
        overload,
        function (original, ...args: any[]) {
            const eventPrefix = getConnectionEventPrefix(this);
            const metadata = getConnectionEventMetadata(
                this,
                declaringClassName,
                target.overloadSignature
            );
            const suppressEvent = shouldSuppressConnectionEvent(eventPrefix);
            const java_stack_trace = collectJavaStackTrace();
            const stackTraceMetadata = java_stack_trace ? { java_stack_trace } : {};

            if (target.methodName === "setRequestMethod") {
                if (eventPrefix && !suppressEvent) {
                    createWebEventSafely(`${eventPrefix}.request_method`, {
                        url: getConnectionUrl(this),
                        method: args[0],
                        ...metadata,
                        ...stackTraceMetadata
                    });
                }

                return runWithConnectionEventPrefix(
                    eventPrefix,
                    () => callOriginal(original, this, ...args)
                );
            }

            if (target.methodName === "setRequestProperty") {
                if (eventPrefix && !suppressEvent) {
                    createWebEventSafely(`${eventPrefix}.request_property`, {
                        url: getConnectionUrl(this),
                        method: "setRequestProperty",
                        data: `${args[0]}: ${args[1]}`,
                        ...metadata,
                        ...stackTraceMetadata
                    });
                }

                return runWithConnectionEventPrefix(
                    eventPrefix,
                    () => callOriginal(original, this, ...args)
                );
            }

            if (target.methodName === "connect") {
                if (eventPrefix && !suppressEvent) {
                    createWebEventSafely("url.connection", {
                        url: getConnectionUrl(this),
                        req_method: getConnectionMethod(this),
                        ...metadata,
                        ...stackTraceMetadata
                    });
                }

                const result = runWithConnectionEventPrefix(
                    eventPrefix,
                    () => callOriginal(original, this, ...args)
                );

                if (eventPrefix && !suppressEvent) {
                    createWebEventSafely(`${eventPrefix}.connect`, {
                        url: getConnectionUrl(this),
                        method: getConnectionMethod(this),
                        ...metadata,
                        ...stackTraceMetadata
                    });
                }

                return result;
            }

            if (target.methodName === "getInputStream") {
                const inputStream = runWithConnectionEventPrefix(
                    eventPrefix,
                    () => callOriginal(original, this, ...args)
                );

                if (eventPrefix && !suppressEvent) {
                    createWebEventSafely(`${eventPrefix}.input_stream`, {
                        url: getConnectionUrl(this),
                        method: getConnectionMethod(this),
                        ...metadata,
                        ...stackTraceMetadata
                    });
                }

                return inputStream;
            }

            if (target.methodName === "getOutputStream") {
                const outputStream = runWithConnectionEventPrefix(
                    eventPrefix,
                    () => callOriginal(original, this, ...args)
                );

                if (eventPrefix && !suppressEvent) {
                    createWebEventSafely(`${eventPrefix}.output_stream`, {
                        url: getConnectionUrl(this),
                        method: getConnectionMethod(this),
                        ...metadata,
                        ...stackTraceMetadata
                    });
                }

                return outputStream;
            }

            if (target.methodName === "getResponseCode") {
                const responseCode = runWithConnectionEventPrefix(
                    eventPrefix,
                    () => callOriginal(original, this, ...args)
                );

                if (eventPrefix && !suppressEvent) {
                    createWebEventSafely(`${eventPrefix}.response_code`, {
                        url: getConnectionUrl(this),
                        method: getConnectionMethod(this),
                        status_code: responseCode,
                        ...metadata,
                        ...stackTraceMetadata
                    });
                }

                return responseCode;
            }

            return runWithConnectionEventPrefix(
                eventPrefix,
                () => callOriginal(original, this, ...args)
            );
        }
    );
}

function installConnectionProviderHooks(connection: any): void {
    try {
        const providerClass = getRuntimeJavaClass(connection);

        if (!providerClass || !getConnectionEventPrefixFromClass(providerClass)) {
            return;
        }

        for (const target of connectionHookTargets) {
            let currentClass = providerClass;

            while (currentClass) {
                if (classDeclaresMethod(currentClass, target)) {
                    installConnectionMethodHook(currentClass, target);
                    break;
                }

                currentClass = currentClass.getSuperclass();
            }
        }
    } catch (error) {
        devlog(`[HOOK] Failed to install URL connection provider hooks: ${error}`);
    }
}

function hookUrlOpenConnection(
    URL: any,
    context: string,
    ...parameterTypes: string[]
): void {
    const overloadSignature = parameterTypes.length === 0
        ? "openConnection()"
        : `openConnection(${parameterTypes.join(",")})`;

    const openConnection = safeOverload(
        URL.openConnection,
        context,
        ...parameterTypes
    );
    if (!openConnection) {
        return;
    }

    openConnection.implementation = safeImplementation(
        context,
        openConnection,
        function (original, ...args: any[]) {
            const result = callOriginal(original, this, ...args);
            const java_stack_trace = collectJavaStackTrace();

            createWebEventSafely("url.open_connection", {
                url: getConnectionUrl(result),
                req_method: getConnectionMethod(result),
                provider_class: getRuntimeProviderClass(result),
                declaring_class: "java.net.URL",
                overload_signature: overloadSignature,
                ...(java_stack_trace ? { java_stack_trace } : {})
            });

            // Provider inspection occurs after the original returns.
            // A discovery failure must not call openConnection() again.
            installConnectionProviderHooks(result);

            return result;
        }
    );
}

function install_url_hooks() {
    devlog("Installing URL hooks");

    safePerform("web:install_url_hooks", () => {
        const URL = safeUse("java.net.URL", "web:install_url_hooks");
        if (URL) {
            // Hook URL constructor
            const urlInit = safeOverload(
                URL.$init,
                "web:URL.$init",
                'java.lang.String'
            );
            if (urlInit) {
                urlInit.implementation = safeImplementation(
                    "web:URL.$init",
                    urlInit,
                    function(original, urlString: string) {
                        const result = original.call(this, urlString);
                        if (!urlString.startsWith("null")) {
                            const java_stack_trace = collectJavaStackTrace();
                            createWebEvent("url.creation", {
                                url: urlString,
                                req_method: "GET",
                                ...(java_stack_trace ? { java_stack_trace } : {})
                            });
                        }
                        return result;
                    }
                );
            }

            // Hook URL openConnection
            hookUrlOpenConnection(
                URL,
                "web:URL.openConnection"
            );

            // Hook URL openConnection(Proxy)
            hookUrlOpenConnection(
                URL,
                "web:URL.openConnection[Proxy]",
                "java.net.Proxy"
            );
        }

        const URI = safeUse("java.net.URI", "web:install_url_hooks");
        if (URI) {
            // Hook URI constructor
            const uriInit = safeOverload(
                URI.$init,
                "web:URI.$init",
                'java.lang.String'
            );
            if (uriInit) {
                uriInit.implementation = safeImplementation(
                    "web:URI.$init",
                    uriInit,
                    function(original, uriString: string) {
                        const result = original.call(this, uriString);
                        const java_stack_trace = collectJavaStackTrace();
                        createWebEvent("uri.creation", {
                            class: "java.net.URI",
                            method: "URI(String)",
                            uri: uriString,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return result;
                    }
                );
            }
        }
    });
}

function install_http_hooks() {
    devlog("HTTP connection hooks use runtime URL provider discovery");
}

function install_https_hooks() {
    devlog("HTTPS connection hooks use runtime URL provider discovery");
}

function install_okhttp_hooks() {
    devlog("Installing OkHTTP hooks");

    safePerform("web:install_okhttp_hooks", () => {
        // Hook OkHttp3 client
        const OkHttpClient = safeUse(
            'okhttp3.OkHttpClient',
            "web:install_okhttp_hooks"
        );
        if (OkHttpClient) {
            const newCall = safeOverload(
                OkHttpClient.newCall,
                "web:OkHttpClient.newCall",
                'okhttp3.Request'
            );
            if (newCall) {
                newCall.implementation = safeImplementation(
                    "web:OkHttpClient.newCall",
                    newCall,
                    function(original, request: any) {
                        const headers: Record<string, string> = {};
                        try {
                            const requestHeaders = request.headers();
                            const headerNames = requestHeaders.names().toArray();
                            for (let i = 0; i < headerNames.length; i++) {
                                headers[headerNames[i]] = requestHeaders.get(headerNames[i]);
                            }
                        } catch (e) {
                            devlog(`Error reading OkHttp headers: ${e}`);
                        }
                        const java_stack_trace = collectJavaStackTrace();
                        createWebEvent("okhttp.request", {
                            url: request.url().toString(),
                            method: request.method(),
                            headers: headers,
                            body: request.body() ? request.body().toString() : null,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return original.call(this, request);
                    }
                );
            }
        }

        // Hook legacy OkHttp client
        const OkHttpClientOld = safeUse(
            "com.squareup.okhttp.OkHttpClient",
            "web:install_okhttp_hooks"
        );
        if (OkHttpClientOld) {
            const newCallOld = safeOverload(
                OkHttpClientOld.newCall,
                "web:com.squareup.okhttp.OkHttpClient.newCall",
                "com.squareup.okhttp.Request"
            );
            if (newCallOld) {
                newCallOld.implementation = safeImplementation(
                    "web:com.squareup.okhttp.OkHttpClient.newCall",
                    newCallOld,
                    function(original, request: any) {
                        const java_stack_trace = collectJavaStackTrace();
                        createWebEventSafely("okhttp_old.request", {
                            url: request.url().toString(),
                            method: request.method(),
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });

                        return callOriginal(original, this, request);
                    }
                );
            }
        }
    });
}

const webSocketSendHookRegistry = new Set<string>();

function installWebSocketSendHook(webSocket: any): void {
    try {
        let currentClass = getRuntimeJavaClass(webSocket);

        if (!currentClass) {
            devlog("[HOOK] WebSocket runtime class is unavailable");
            return;
        }

        while (currentClass) {
            const className = getJavaClassName(currentClass);

            const target = {
                methodName: "send",
                parameterTypes: ["java.lang.String"],
                overloadSignature: "send(java.lang.String)"
            };

            if (classDeclaresMethod(currentClass, target)) {

                let classLoader: any = null;

                try {
                    classLoader = currentClass.getClassLoader();
                } catch (_) {
                    classLoader = null;
                }

                const classLoaderIdentity = getClassLoaderIdentity(currentClass);
                const registryKey = [
                    classLoaderIdentity,
                    className,
                    target.overloadSignature
                ].join("|");

                if (webSocketSendHookRegistry.has(registryKey)) {
                    return;
                }

                webSocketSendHookRegistry.add(registryKey);

                const context = `web:${className}.${target.overloadSignature}`;
                const WebSocketImplementation = safeUseFromClassLoader(
                    className,
                    classLoader,
                    context
                );
                if (!WebSocketImplementation) {
                    return;
                }

                const sendText = safeOverload(
                    WebSocketImplementation.send,
                    context,
                    "java.lang.String"
                );
                if (!sendText) {
                    return;
                }

                sendText.implementation = safeImplementation(
                    context,
                    sendText,
                    function(original, text: string) {
                        const java_stack_trace = collectJavaStackTrace();
                        createWebEventSafely("websocket.send_text", {
                            url: getWebSocketUrl(this),
                            data: text.length > 200
                                ? text.substring(0, 200) + "..."
                                : text,
                            method: "send",
                            provider_class: getRuntimeProviderClass(this),
                            declaring_class: className,
                            overload_signature: target.overloadSignature,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });

                        return callOriginal(original, this, text);
                    }
                );

                return;
            }

            currentClass = currentClass.getSuperclass();
        }
    } catch (error) {
        devlog(`[HOOK] Failed to install WebSocket send hook: ${error}`);
    }
}

const webSocketListenerHookRegistry = new Set<string>();

interface RuntimeMethodHookLocation {
    declaringClass: any;
    declaringClassName: string;
    target: RuntimeMethodHookTarget;
}

function findRuntimeMethod(
    instance: any,
    matcher: (methodName: string, parameterTypes: string[]) => boolean
): RuntimeMethodHookLocation | null {
    const runtimeClass = getRuntimeJavaClass(instance);

    if (!runtimeClass) {
        return null;
    }

    let currentClass = runtimeClass;

    while (currentClass) {
        try {
            const methods = currentClass.getDeclaredMethods();

            for (let i = 0; i < methods.length; i++) {
                const method = methods[i];
                const modifiers = method.getModifiers();

                // Ignore static and abstract declarations.
                if ((modifiers & 0x0008) !== 0 || (modifiers & 0x0400) !== 0) {
                    continue;
                }

                const methodName = method.getName().toString();
                const reflectedParameterTypes = method.getParameterTypes();
                const parameterTypes: string[] = [];

                for (let j = 0; j < reflectedParameterTypes.length; j++) {
                    parameterTypes.push(
                        reflectedParameterTypes[j].getName().toString()
                    );
                }

                if (!matcher(methodName, parameterTypes)) {
                    continue;
                }

                return {
                    declaringClass: currentClass,
                    declaringClassName: getJavaClassName(currentClass),
                    target: {
                        methodName: methodName,
                        parameterTypes: parameterTypes,
                        overloadSignature:
                            `${methodName}(${parameterTypes.join(",")})`
                    }
                };
            }
        } catch (error) {
            devlog(
                `[HOOK] Failed to inspect WebSocket listener class ` +
                `${getJavaClassName(currentClass)}: ${error}`
            );
            return null;
        }

        currentClass = currentClass.getSuperclass();
    }

    return null;
}

function getListenerHookRegistryKey(
    location: RuntimeMethodHookLocation
): string {
    return [
        getClassLoaderIdentity(location.declaringClass),
        location.declaringClassName,
        location.target.overloadSignature
    ].join("|");
}

function installWebSocketOpenedListenerHook(listener: any): void {
    const location = findRuntimeMethod(
        listener,
        (methodName, parameterTypes) =>
            methodName === "onOpen" &&
            parameterTypes.length === 2 &&
            parameterTypes[0] === "okhttp3.WebSocket" &&
            parameterTypes[1] === "okhttp3.Response"
    );

    if (!location) {
        return;
    }

    const registryKey = getListenerHookRegistryKey(location);

    if (webSocketListenerHookRegistry.has(registryKey)) {
        return;
    }

    webSocketListenerHookRegistry.add(registryKey);

    let classLoader: any = null;

    try {
        classLoader = location.declaringClass.getClassLoader();
    } catch (_) {
        classLoader = null;
    }

    const context =
        `web:${location.declaringClassName}.` +
        `${location.target.overloadSignature}`;

    const ListenerClass = safeUseFromClassLoader(
        location.declaringClassName,
        classLoader,
        context
    );
    if (!ListenerClass) {
        return;
    }

    const onOpen = safeOverload(
        ListenerClass[location.target.methodName],
        context,
        ...location.target.parameterTypes
    );
    if (!onOpen) {
        return;
    }

    onOpen.implementation = safeImplementation(
        context,
        onOpen,
        function(original, webSocket: any, response: any) {
            const java_stack_trace = collectJavaStackTrace();
            createWebEventSafely("websocket.opened", {
                url: getWebSocketUrl(webSocket, response),
                status_code: getWebSocketResponseCode(response),
                method: location.target.methodName,
                ...getWebSocketMetadata(
                    webSocket,
                    location.declaringClassName,
                    location.target.overloadSignature
                ),
                ...(java_stack_trace ? { java_stack_trace } : {})
            });

            return callOriginal(original, this, webSocket, response);
        }
    );
}

function installWebSocketMessageListenerHook(listener: any): void {
    const location = findRuntimeMethod(
        listener,
        (methodName, parameterTypes) =>
            methodName === "onMessage" &&
            parameterTypes.length === 2 &&
            parameterTypes[0] === "okhttp3.WebSocket" &&
            parameterTypes[1] === "java.lang.String"
    );

    if (!location) {
        return;
    }

    const registryKey = getListenerHookRegistryKey(location);

    if (webSocketListenerHookRegistry.has(registryKey)) {
        return;
    }

    webSocketListenerHookRegistry.add(registryKey);

    let classLoader: any = null;

    try {
        classLoader = location.declaringClass.getClassLoader();
    } catch (_) {
        classLoader = null;
    }

    const context =
        `web:${location.declaringClassName}.` +
        `${location.target.overloadSignature}`;

    const ListenerClass = safeUseFromClassLoader(
        location.declaringClassName,
        classLoader,
        context
    );
    if (!ListenerClass) {
        return;
    }

    const onMessage = safeOverload(
        ListenerClass[location.target.methodName],
        context,
        ...location.target.parameterTypes
    );
    if (!onMessage) {
        return;
    }

    onMessage.implementation = safeImplementation(
        context,
        onMessage,
        function(original, webSocket: any, text: string) {
            const java_stack_trace = collectJavaStackTrace();
            createWebEventSafely("websocket.message_received", {
                url: getWebSocketUrl(webSocket),
                data: text.length > 200
                    ? text.substring(0, 200) + "..."
                    : text,
                method: location.target.methodName,
                ...getWebSocketMetadata(
                    webSocket,
                    location.declaringClassName,
                    location.target.overloadSignature
                ),
                ...(java_stack_trace ? { java_stack_trace } : {})
            });

            return callOriginal(original, this, webSocket, text);
        }
    );
}


function getWebSocketResponseUrl(response: any): string {
    try {
        return response.request().url().toString();
    } catch (_) {
        return "unknown";
    }
}

function normalizeWebSocketUrl(url: string): string {
    if (url.startsWith("http://")) {
        return `ws://${url.substring("http://".length)}`;
    }

    if (url.startsWith("https://")) {
        return `wss://${url.substring("https://".length)}`;
    }

    return url;
}

function getWebSocketUrl(webSocket: any, response?: any): string {
    try {
        const request = webSocket.request();

        if (request) {
            return normalizeWebSocketUrl(request.url().toString());
        }
    } catch (_) {
        // Fall through to the upgrade response URL.
    }

    if (response) {
        return normalizeWebSocketUrl(getWebSocketResponseUrl(response));
    }

    return "unknown";
}

function getWebSocketResponseCode(response: any): number | undefined {
    try {
        return response.code();
    } catch (_) {
        return undefined;
    }
}

function getWebSocketMetadata(
    webSocket: any,
    declaringClassName: string,
    overloadSignature: string
): Partial<WebEvent> {
    return {
        provider_class: getRuntimeProviderClass(webSocket),
        declaring_class: declaringClassName,
        overload_signature: overloadSignature
    };
}

function install_websocket_hooks() {
    devlog("Installing WebSocket hooks");

    safePerform("web:install_websocket_hooks", () => {
        const OkHttpClient = safeUse(
            "okhttp3.OkHttpClient",
            "web:install_websocket_hooks"
        );
        if (!OkHttpClient) {
            return;
        }

        const newWebSocket = safeOverload(
            OkHttpClient.newWebSocket,
            "web:OkHttpClient.newWebSocket",
            "okhttp3.Request",
            "okhttp3.WebSocketListener"
        );
        if (!newWebSocket) {
            return;
        }

        newWebSocket.implementation = safeImplementation(
            "web:OkHttpClient.newWebSocket",
            newWebSocket,
            function(original, request: any, listener: any) {
                try {
                    installWebSocketOpenedListenerHook(listener);
                    installWebSocketMessageListenerHook(listener);
                } catch (error) {
                    devlog(
                        `[HOOK] Failed to inspect WebSocket listener: ${error}`
                    );
                }

                const webSocket = callOriginal(
                    original,
                    this,
                    request,
                    listener
                );

                try {
                    installWebSocketSendHook(webSocket);
                } catch (error) {
                    devlog(
                        `[HOOK] Failed to inspect WebSocket implementation: ${error}`
                    );
                }

                return webSocket;
            }
        );
    });
}

function install_webview_hooks() {
    devlog("Installing WebView hooks");

    safePerform("web:install_webview_hooks", () => {
        // Hook WebView.loadUrl (single argument)
        const WebView = safeUse("android.webkit.WebView", "web:install_webview_hooks");
        if (WebView) {
            const loadUrlBasic = safeOverload(
                WebView.loadUrl,
                "web:WebView.loadUrl",
                'java.lang.String'
            );
            if (loadUrlBasic) {
                loadUrlBasic.implementation = safeImplementation(
                    "web:WebView.loadUrl[String]",
                    loadUrlBasic,
                    function(original, url: string) {
                        const java_stack_trace = collectJavaStackTrace();
                        createWebEvent("webview.load_url", {
                            url: url,
                            method: "loadUrl",
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return original.call(this, url);
                    }
                );
            }

            // safeOverload replaces the original overloads.length > 1 check
            // Hook WebView.loadUrl (with headers)
            const loadUrlWithHeaders = safeOverload(
                WebView.loadUrl,
                "web:WebView.loadUrl",
                'java.lang.String', 'java.util.Map'
            );
            if (loadUrlWithHeaders) {
                loadUrlWithHeaders.implementation = safeImplementation(
                    "web:WebView.loadUrl[String,Map]",
                    loadUrlWithHeaders,
                    function(original, url: string, additionalHttpHeaders: any) {
                        const java_stack_trace = collectJavaStackTrace();
                        createWebEvent("webview.load_url_with_headers", {
                            url: url,
                            headers: additionalHttpHeaders || {},
                            method: "loadUrl",
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return original.call(this, url, additionalHttpHeaders);
                    }
                );
            }

            // Hook WebView.loadData
            const loadDataRef = WebView.loadData;
            loadDataRef.implementation = safeImplementation(
                "web:WebView.loadData",
                loadDataRef,
                function(original, data: string, mimeType: string, encoding: string) {
                    const java_stack_trace = collectJavaStackTrace();
                    createWebEvent("webview.load_data", {
                        data: data.length > 100 ? data.substring(0, 100) + "..." : data,
                        mime_type: mimeType,
                        encoding: encoding,
                        method: "loadData",
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });
                    return original.call(this, data, mimeType, encoding);
                }
            );

            // Hook WebView.postUrl
            const postUrlRef = WebView.postUrl;
            if (postUrlRef) {
                postUrlRef.implementation = safeImplementation(
                    "web:WebView.postUrl",
                    postUrlRef,
                    function(original, url: string, postData: any) {
                        const java_stack_trace = collectJavaStackTrace();
                        createWebEvent("webview.post_url", {
                            url: url,
                            method: "postUrl",
                            data: postData ? `[Binary data: ${postData.length} bytes]` : null,
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return original.call(this, url, postData);
                    }
                );
            }
        }

        // Hook WebViewClient callbacks
        const WebViewClient = safeUse(
            "android.webkit.WebViewClient",
            "web:install_webview_hooks"
        );
        if (WebViewClient) {
            const onPageStartedRef = WebViewClient.onPageStarted;
            onPageStartedRef.implementation = safeImplementation(
                "web:WebViewClient.onPageStarted",
                onPageStartedRef,
                function(original, view: any, url: string, favicon: any) {
                    const java_stack_trace = collectJavaStackTrace();
                    createWebEvent("webview.page_started", {
                        url: url,
                        method: "onPageStarted",
                        ...(java_stack_trace ? { java_stack_trace } : {})
                    });
                    return original.call(this, view, url, favicon);
                }
            );

            const onPageFinishedRef = WebViewClient.onPageFinished;
            onPageFinishedRef.implementation = safeImplementation(
                "web:WebViewClient.onPageFinished",
                onPageFinishedRef,
                function(original, view: any, url: string) {
                        const java_stack_trace = collectJavaStackTrace();
                        createWebEvent("webview.page_finished", {
                            url: url,
                            method: "onPageFinished",
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return original.call(this, view, url);
                }
            );

            const shouldOverride = safeOverload(
                WebViewClient.shouldOverrideUrlLoading,
                "web:WebViewClient.shouldOverrideUrlLoading",
                'android.webkit.WebView', 'java.lang.String'
            );
            if (shouldOverride) {
                shouldOverride.implementation = safeImplementation(
                    "web:WebViewClient.shouldOverrideUrlLoading",
                    shouldOverride,
                    function(original, view: any, url: string) {
                        const java_stack_trace = collectJavaStackTrace();
                        createWebEvent("webview.url_override", {
                            url: url,
                            method: "shouldOverrideUrlLoading",
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return original.call(this, view, url);
                    }
                );
            }
        }
    });
}

function install_retrofit_hooks() {
    devlog("Installing Retrofit hooks");

    safePerform("web:install_retrofit_hooks", () => {
        const OkHttpCall = safeUse(
            "retrofit2.OkHttpCall",
            "web:install_retrofit_hooks"
        );
        if (!OkHttpCall) {
            return;
        }

        const execute = safeOverload(
            OkHttpCall.execute,
            "web:OkHttpCall.execute"
        );
        if (execute) {
            execute.implementation = safeImplementation(
                "web:OkHttpCall.execute",
                execute,
                function(original) {
                    const request = this.request();
                    const java_stack_trace = collectJavaStackTrace();

                    if (request) {
                        createWebEventSafely("retrofit.request", {
                            url: request.url().toString(),
                            method: request.method(),
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                    }

                    const response = callOriginal(original, this);

                    if (response) {
                        createWebEventSafely("retrofit.response", {
                            url: request ? request.url().toString() : "unknown",
                            status_code: response.code(),
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                    }

                    return response;
                }
            );
        }

        const enqueue = safeOverload(
            OkHttpCall.enqueue,
            "web:OkHttpCall.enqueue",
            "retrofit2.Callback"
        );
        if (enqueue) {
            enqueue.implementation = safeImplementation(
                "web:OkHttpCall.enqueue",
                enqueue,
                function(original, callback: any) {
                    const request = this.request();

                    if (request) {
                        const java_stack_trace = collectJavaStackTrace();
                        createWebEventSafely("retrofit.async_request", {
                            url: request.url().toString(),
                            method: request.method(),
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                    }

                    return callOriginal(original, this, callback);
                }
            );
        }
    });
}

function install_volley_hooks() {
    devlog("Installing Volley hooks");

    safePerform("web:install_volley_hooks", () => {
        const StringRequest = safeUse(
            'com.android.volley.toolbox.StringRequest',
            "web:install_volley_hooks"
        );
        if (StringRequest) {
            const volleyInit = safeOverload(
                StringRequest.$init,
                "web:StringRequest.$init",
                'int', 'java.lang.String',
                'com.android.volley.Response$Listener',
                'com.android.volley.Response$ErrorListener'
            );
            if (volleyInit) {
                volleyInit.implementation = safeImplementation(
                    "web:StringRequest.$init",
                    volleyInit,
                    function(original, method: number, url: string, listener: any, errorListener: any) {
                        const java_stack_trace = collectJavaStackTrace();
                        createWebEvent("volley.string_request", {
                            url: url,
                            method: method === 0 ? "GET" : method === 1 ? "POST" :
                                method === 2 ? "PUT" : method === 3 ? "DELETE" : "UNKNOWN",
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                        return original.call(this, method, url, listener, errorListener);
                    }
                );
            }
        }

        const RequestQueue = safeUse(
            'com.android.volley.RequestQueue',
            "web:install_volley_hooks"
        );
        if (RequestQueue) {
            const addRef = RequestQueue.add;
            addRef.implementation = safeImplementation(
                "web:RequestQueue.add",
                addRef,
                function(original, request: any) {
                    if (request.getUrl) {
                        const java_stack_trace = collectJavaStackTrace();
                        createWebEvent("volley.queue_request", {
                            url: request.getUrl(),
                            method: request.getMethod ? request.getMethod().toString() : "UNKNOWN",
                            ...(java_stack_trace ? { java_stack_trace } : {})
                        });
                    }
                    return original.call(this, request);
                }
            );
        }
    });
}


export function install_web_hooks() {
    devlog("\n");
    devlog("Installing comprehensive web hooks");

    // Core HTTP/HTTPS hooks
    try {
        install_url_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install URL hooks: ${error}`);
    }

    try {
        install_http_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install HTTP hooks: ${error}`);
    }

    try {
        install_https_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install HTTPS hooks: ${error}`);
    }

    // Popular HTTP libraries
    try {
        install_okhttp_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install OkHTTP hooks: ${error}`);
    }

    try {
        install_retrofit_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install Retrofit hooks: ${error}`);
    }

    try {
        install_volley_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install Volley hooks: ${error}`);
    }

    // WebSocket communication
    try {
        install_websocket_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install WebSocket hooks: ${error}`);
    }

    // WebView and browser components
    try {
        install_webview_hooks();
    } catch (error) {
        devlog(`[HOOK] Failed to install WebView hooks: ${error}`);
    }

    devlog("Comprehensive web hooks installation completed");
}