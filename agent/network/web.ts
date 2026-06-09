import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Where } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"
import { safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"

const PROFILE_HOOKING_TYPE: string = "WEB"

interface WebEvent {
    event_type: string;
    timestamp: number;
    url?: string;
    method?: string;
    headers?: Record<string, any> | string;
    body?: string;
    stack_trace?: string;
    class?: string;
    uri?: string;
    req_method?: string;
    status_code?: number;
    data?: string;
    mime_type?: string;
    encoding?: string;
}

function createWebEvent(eventType: string, data: Partial<WebEvent>): void {
    const event: WebEvent = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
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
                            createWebEvent("url.creation", {
                                url: urlString,
                                req_method: "GET"
                            });
                        }
                        return result;
                    }
                );
            }

            // Hook URL openConnection
            const openConnection = safeOverload(
                URL.openConnection,
                "web:URL.openConnection"
            );
            if (openConnection) {
                openConnection.implementation = safeImplementation(
                    "web:URL.openConnection",
                    openConnection,
                    function(original) {
                        const result = original.call(this);
                        createWebEvent("url.open_connection", {
                            url: result.getURL().toString(),
                            req_method: "GET"
                        });
                        return result;
                    }
                );
            }
        }

        const HttpURLConnection = safeUse(
            "java.net.HttpURLConnection",
            "web:install_url_hooks"
        );
        if (HttpURLConnection) {
            // note: connect is also hooked in install_http_hooks below with more detail
            // second assignment will overwrite this one
            // Hook connection
            const connectRef = HttpURLConnection.connect;
            connectRef.implementation = safeImplementation(
                "web:HttpURLConnection.connect[url_hooks]",
                connectRef,
                function(original) {
                    createWebEvent("url.connection", {
                        url: this.getURL ? this.getURL().toString() : "unknown",
                        req_method: this.getRequestMethod ? this.getRequestMethod() : "GET"
                    });
                    return original.call(this);
                }
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
                        createWebEvent("uri.creation", {
                            class: "java.net.URI",
                            method: "URI(String)",
                            uri: uriString
                        });
                        return result;
                    }
                );
            }
        }
    });
}

function install_http_hooks() {
    devlog("Installing HTTP communication hooks");

    safePerform("web:install_http_hooks", () => {
        const HttpURLConnection = safeUse(
            "java.net.HttpURLConnection",
            "web:install_http_hooks"
        );
        if (!HttpURLConnection) return;

        // Hook request method setting
        const setRequestMethodRef = HttpURLConnection.setRequestMethod;
        setRequestMethodRef.implementation = safeImplementation(
            "web:HttpURLConnection.setRequestMethod",
            setRequestMethodRef,
            function(original, method: string) {
                createWebEvent("http.request_method", {
                    method: method,
                    url: this.getURL ? this.getURL().toString() : "unknown"
                });
                return original.call(this, method);
            }
        );

        // Hook connection
        const connectRef = HttpURLConnection.connect;
        connectRef.implementation = safeImplementation(
            "web:HttpURLConnection.connect[http_hooks]",
            connectRef,
            function(original) {
                const result = original.call(this);
                // inner try-catch intentional: getResponseCode() can throw on some implementations
                try {
                    const responseCode = this.getResponseCode();
                    createWebEvent("http.connect", {
                        url: this.getURL ? this.getURL().toString() : "unknown",
                        status_code: responseCode,
                        method: this.getRequestMethod ? this.getRequestMethod() : "GET"
                    });
                } catch (e) {
                    createWebEvent("http.connect", {
                        url: this.getURL ? this.getURL().toString() : "unknown",
                        method: this.getRequestMethod ? this.getRequestMethod() : "GET"
                    });
                }
                return result;
            }
        );

        // Hook output stream (for request body)
        const getOutputStreamRef = HttpURLConnection.getOutputStream;
        getOutputStreamRef.implementation = safeImplementation(
            "web:HttpURLConnection.getOutputStream",
            getOutputStreamRef,
            function(original) {
                const outputStream = original.call(this);
                createWebEvent("http.output_stream", {
                    url: this.getURL ? this.getURL().toString() : "unknown",
                    method: this.getRequestMethod ? this.getRequestMethod() : "GET"
                });
                return outputStream;
            }
        );

        // Hook input stream (for response body)
        const getInputStreamRef = HttpURLConnection.getInputStream;
        getInputStreamRef.implementation = safeImplementation(
            "web:HttpURLConnection.getInputStream",
            getInputStreamRef,
            function(original) {
                const inputStream = original.call(this);
                createWebEvent("http.input_stream", {
                    url: this.getURL ? this.getURL().toString() : "unknown",
                    method: this.getRequestMethod ? this.getRequestMethod() : "GET"
                });
                return inputStream;
            }
        );
    });
}

function install_https_hooks() {
    devlog("Installing HTTPS communication hooks");

    safePerform("web:install_https_hooks", () => {
        const HttpsURLConnection = safeUse(
            "javax.net.ssl.HttpsURLConnection",
            "web:install_https_hooks"
        );
        if (!HttpsURLConnection) return;

        // Hook HTTPS request method setting
        const setRequestMethodRef = HttpsURLConnection.setRequestMethod;
        setRequestMethodRef.implementation = safeImplementation(
            "web:HttpsURLConnection.setRequestMethod",
            setRequestMethodRef,
            function(original, method: string) {
                createWebEvent("https.request_method", {
                    method: method,
                    url: this.getURL ? this.getURL().toString() : "unknown"
                });
                return original.call(this, method);
            }
        );

        // Hook HTTPS connection
        const connectRef = HttpsURLConnection.connect;
        connectRef.implementation = safeImplementation(
            "web:HttpsURLConnection.connect",
            connectRef,
            function(original) {
                const result = original.call(this);
                try {
                    const responseCode = this.getResponseCode();
                    createWebEvent("https.connect", {
                        url: this.getURL ? this.getURL().toString() : "unknown",
                        status_code: responseCode,
                        method: this.getRequestMethod ? this.getRequestMethod() : "GET"
                    });
                } catch (e) {
                    createWebEvent("https.connect", {
                        url: this.getURL ? this.getURL().toString() : "unknown",
                        method: this.getRequestMethod ? this.getRequestMethod() : "GET"
                    });
                }
                return result;
            }
        );

        // Hook HTTPS input stream
        const getInputStreamRef = HttpsURLConnection.getInputStream;
        getInputStreamRef.implementation = safeImplementation(
            "web:HttpsURLConnection.getInputStream",
            getInputStreamRef,
            function(original) {
                const inputStream = original.call(this);
                createWebEvent("https.input_stream", {
                    url: this.getURL ? this.getURL().toString() : "unknown",
                    method: this.getRequestMethod ? this.getRequestMethod() : "GET"
                });
                return inputStream;
            }
        );
    });
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
                        createWebEvent("okhttp.request", {
                            url: request.url().toString(),
                            method: request.method(),
                            headers: headers,
                            body: request.body() ? request.body().toString() : null
                        });
                        return original.call(this, request);
                    }
                );
            }
        }

        // Hook legacy OkHttp client
        const OkHttpClientOld = safeUse(
            'okhttp.OkHttpClient',
            "web:install_okhttp_hooks"
        );
        if (OkHttpClientOld) {
            const newCallOld = safeOverload(
                OkHttpClientOld.newCall,
                "web:okhttp.OkHttpClient.newCall",
                'okhttp.Request'
            );
            if (newCallOld) {
                newCallOld.implementation = safeImplementation(
                    "web:okhttp.OkHttpClient.newCall",
                    newCallOld,
                    function(original, request: any) {
                        createWebEvent("okhttp_old.request", {
                            url: request.url().toString(),
                            method: request.method()
                        });
                        return original.call(this, request);
                    }
                );
            }
        }

        // Hook HttpURLConnectionImpl from OkHttp
        const HttpURLConnectionImpl = safeUse(
            "com.android.okhttp.internal.huc.HttpURLConnectionImpl",
            "web:install_okhttp_hooks"
        );
        if (HttpURLConnectionImpl) {
            const setRequestPropertyRef = HttpURLConnectionImpl.setRequestProperty;
            setRequestPropertyRef.implementation = safeImplementation(
                "web:HttpURLConnectionImpl.setRequestProperty",
                setRequestPropertyRef,
                function(original, name: string, value: string) {
                    createWebEvent("okhttp.request_property", {
                        url: this.getURL ? this.getURL().toString() : "unknown",
                        method: "setRequestProperty",
                        data: `${name}: ${value}`
                    });
                    return original.call(this, name, value);
                }
            );

            const setRequestMethodRef = HttpURLConnectionImpl.setRequestMethod;
            setRequestMethodRef.implementation = safeImplementation(
                "web:HttpURLConnectionImpl.setRequestMethod",
                setRequestMethodRef,
                function(original, method: string) {
                    createWebEvent("okhttp.request_method", {
                        url: this.getURL ? this.getURL().toString() : "unknown",
                        method: method
                    });
                    return original.call(this, method);
                }
            );
        }
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
                        createWebEvent("webview.load_url", {
                            url: url,
                            method: "loadUrl"
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
                        createWebEvent("webview.load_url_with_headers", {
                            url: url,
                            headers: additionalHttpHeaders || {},
                            method: "loadUrl"
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
                    createWebEvent("webview.load_data", {
                        data: data.length > 100 ? data.substring(0, 100) + "..." : data,
                        mime_type: mimeType,
                        encoding: encoding,
                        method: "loadData"
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
                        createWebEvent("webview.post_url", {
                            url: url,
                            method: "postUrl",
                            data: postData ? `[Binary data: ${postData.length} bytes]` : null
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
                    createWebEvent("webview.page_started", {
                        url: url,
                        method: "onPageStarted"
                    });
                    return original.call(this, view, url, favicon);
                }
            );

            const onPageFinishedRef = WebViewClient.onPageFinished;
            onPageFinishedRef.implementation = safeImplementation(
                "web:WebViewClient.onPageFinished",
                onPageFinishedRef,
                function(original, view: any, url: string) {
                        createWebEvent("webview.page_finished", {
                            url: url,
                            method: "onPageFinished"
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
                        createWebEvent("webview.url_override", {
                            url: url,
                            method: "shouldOverrideUrlLoading"
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
            'retrofit2.OkHttpCall',
            "web:install_retrofit_hooks"
        );
        if (OkHttpCall) {
            const executeRef = OkHttpCall.execute;
            executeRef.implementation = safeImplementation(
                "web:OkHttpCall.execute",
                executeRef,
                function(original) {
                    const request = this.request();
                    if (request) {
                        createWebEvent("retrofit.request", {
                            url: request.url().toString(),
                            method: request.method()
                        });
                    }
                    const response = original.call(this);
                    if (response) {
                        createWebEvent("retrofit.response", {
                            url: request ? request.url().toString() : "unknown",
                            status_code: response.code()
                        });
                    }
                    return response;
                }
            );
        }

        const Call = safeUse('retrofit2.Call', "web:install_retrofit_hooks");
        if (Call) {
            const enqueueRef = Call.enqueue;
            enqueueRef.implementation = safeImplementation(
                "web:Call.enqueue",
                enqueueRef,
                function(original, callback: any) {
                    const request = this.request();
                    if (request) {
                        createWebEvent("retrofit.async_request", {
                            url: request.url().toString(),
                            method: request.method()
                        });
                    }
                    return original.call(this, callback);
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
                        createWebEvent("volley.string_request", {
                            url: url,
                            method: method === 0 ? "GET" : method === 1 ? "POST" :
                                method === 2 ? "PUT" : method === 3 ? "DELETE" : "UNKNOWN"
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
                        createWebEvent("volley.queue_request", {
                            url: request.getUrl(),
                            method: request.getMethod ? request.getMethod().toString() : "UNKNOWN"
                        });
                    }
                    return original.call(this, request);
                }
            );
        }
    });
}

function install_websocket_hooks() {
    devlog("Installing WebSocket hooks");

    safePerform("web:install_websocket_hooks", () => {
        const WebSocket = safeUse('okhttp3.WebSocket', "web:install_websocket_hooks");
        if (WebSocket) {
            const sendText = safeOverload(
                WebSocket.send,
                "web:WebSocket.send",
                'java.lang.String'
            );
            if (sendText) {
                sendText.implementation = safeImplementation(
                    "web:WebSocket.send[String]",
                    sendText,
                    function(original, text: string) {
                        createWebEvent("websocket.send_text", {
                            data: text.length > 200 ? text.substring(0, 200) + "..." : text,
                            method: "send"
                        });
                        return original.call(this, text);
                    }
                );
            }
        }

        const WebSocketListener = safeUse(
            'okhttp3.WebSocketListener',
            "web:install_websocket_hooks"
        );
        if (WebSocketListener) {
            const onOpenRef = WebSocketListener.onOpen;
            onOpenRef.implementation = safeImplementation(
                "web:WebSocketListener.onOpen",
                onOpenRef,
                function(original, webSocket: any, response: any) {
                    createWebEvent("websocket.opened", {
                        status_code: response.code(),
                        url: response.request().url().toString()
                    });
                    return original.call(this, webSocket, response);
                }
            );

            const onMessageText = safeOverload(
                WebSocketListener.onMessage,
                "web:WebSocketListener.onMessage",
                'okhttp3.WebSocket', 'java.lang.String'
            );
            if (onMessageText) {
                onMessageText.implementation = safeImplementation(
                    "web:WebSocketListener.onMessage[String]",
                    onMessageText,
                    function(original, webSocket: any, text: string) {
                        createWebEvent("websocket.message_received", {
                            data: text.length > 200 ? text.substring(0, 200) + "..." : text
                        });
                        return original.call(this, webSocket, text);
                    }
                );
            }
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