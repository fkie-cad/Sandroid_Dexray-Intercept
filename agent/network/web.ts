import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Where } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"

const PROFILE_HOOKING_TYPE: string = "WEB"

// Utility functions for safe hook installation
function safeHookClass(className: string, hookFunction: (clazz: any) => void): boolean {
    try {
        const clazz = Java.use(className);
        hookFunction(clazz);
        devlog(`Successfully hooked ${className}`);
        return true;
    } catch (e) {
        devlog(`Class ${className} not available: ${e}`);
        return false;
    }
}

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
    
    Java.perform(() => {
        safeHookClass("java.net.URL", (URL: any) => {
            // Hook URL constructor
            URL.$init.overload('java.lang.String').implementation = function (urlString: string) {
                const result = this.$init(urlString);
                
                if (!urlString.startsWith("null")) {
                    createWebEvent("url.creation", {
                        url: urlString,
                        req_method: "GET"
                    });
                }
                return result;
            };

            // Hook URL openConnection
            URL.openConnection.overload().implementation = function() {
                const result = this.openConnection();
                
                createWebEvent("url.open_connection", {
                    url: result.getURL().toString(),
                    req_method: "GET"
                });
                return result;
            };
        });

        safeHookClass("java.net.HttpURLConnection", (HttpURLConnection: any) => {
            // Hook connection
            HttpURLConnection.connect.implementation = function() {
                createWebEvent("url.connection", {
                    url: this.getURL().toString(),
                    req_method: this.getRequestMethod ? this.getRequestMethod() : "GET"
                });
                return this.connect();
            };
        });

        safeHookClass("java.net.URI", (URI: any) => {
            // Hook URI constructor
            URI.$init.overload('java.lang.String').implementation = function(uriString: string) {
                const result = this.$init(uriString);
                
                createWebEvent("uri.creation", {
                    class: "java.net.URI",
                    method: "URI(String)",
                    uri: uriString
                });
                
                return result;
            };
        });
    });
}

function install_http_hooks() {
    devlog("Installing HTTP communication hooks");
    
    Java.perform(() => {
        safeHookClass("java.net.HttpURLConnection", (HttpURLConnection: any) => {
            // Hook request method setting
            HttpURLConnection.setRequestMethod.implementation = function(method: string) {
                createWebEvent("http.request_method", {
                    method: method,
                    url: this.getURL ? this.getURL().toString() : "unknown"
                });
                return this.setRequestMethod(method);
            };

            // Hook connection
            HttpURLConnection.connect.implementation = function() {
                const result = this.connect();
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
            };

            // Hook output stream (for request body)
            HttpURLConnection.getOutputStream.implementation = function() {
                const outputStream = this.getOutputStream();
                createWebEvent("http.output_stream", {
                    url: this.getURL ? this.getURL().toString() : "unknown",
                    method: this.getRequestMethod ? this.getRequestMethod() : "GET"
                });
                return outputStream;
            };

            // Hook input stream (for response body)
            HttpURLConnection.getInputStream.implementation = function() {
                const inputStream = this.getInputStream();
                const url = this.getURL ? this.getURL().toString() : "unknown";
                const method = this.getRequestMethod ? this.getRequestMethod() : "GET";
                
                createWebEvent("http.input_stream", {
                    url: url,
                    method: method
                });
                
                return inputStream;
            };
        });
    });
}

function install_https_hooks() {
    devlog("Installing HTTPS communication hooks");
    
    Java.perform(() => {
        safeHookClass("javax.net.ssl.HttpsURLConnection", (HttpsURLConnection: any) => {
            // Hook HTTPS request method setting
            HttpsURLConnection.setRequestMethod.implementation = function(method: string) {
                createWebEvent("https.request_method", {
                    method: method,
                    url: this.getURL ? this.getURL().toString() : "unknown"
                });
                return this.setRequestMethod(method);
            };

            // Hook HTTPS connection
            HttpsURLConnection.connect.implementation = function() {
                const result = this.connect();
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
            };

            // Hook HTTPS input stream
            HttpsURLConnection.getInputStream.implementation = function() {
                const inputStream = this.getInputStream();
                const url = this.getURL ? this.getURL().toString() : "unknown";
                const method = this.getRequestMethod ? this.getRequestMethod() : "GET";
                
                createWebEvent("https.input_stream", {
                    url: url,
                    method: method
                });
                
                return inputStream;
            };
        });
    });
}

function install_okhttp_hooks(){
    devlog("Installing OkHTTP hooks");
    
    Java.perform(() => {
        // Hook OkHttp3 client
        safeHookClass('okhttp3.OkHttpClient', (OkHttpClient: any) => {
            OkHttpClient.newCall.overload('okhttp3.Request').implementation = function (request: any) {
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

                return this.newCall(request);
            };
        });

        // Hook legacy OkHttp client
        safeHookClass('okhttp.OkHttpClient', (OkHttpClientOld: any) => {
            OkHttpClientOld.newCall.overload('okhttp.Request').implementation = function (request: any) {
                createWebEvent("okhttp_old.request", {
                    url: request.url().toString(),
                    method: request.method()
                });
                return this.newCall(request);
            };
        });

        // Hook HttpURLConnectionImpl from OkHttp
        safeHookClass("com.android.okhttp.internal.huc.HttpURLConnectionImpl", (HttpURLConnectionImpl: any) => {
            HttpURLConnectionImpl.setRequestProperty.implementation = function (name: string, value: string) {
                createWebEvent("okhttp.request_property", {
                    url: this.getURL ? this.getURL().toString() : "unknown",
                    method: "setRequestProperty",
                    data: `${name}: ${value}`
                });
                return this.setRequestProperty(name, value);
            };

            HttpURLConnectionImpl.setRequestMethod.implementation = function (method: string) {
                createWebEvent("okhttp.request_method", {
                    url: this.getURL ? this.getURL().toString() : "unknown",
                    method: method
                });
                return this.setRequestMethod(method);
            };
        });
    });
}

function install_webview_hooks(){
    devlog("Installing WebView hooks");
    
    Java.perform(() => {
        safeHookClass("android.webkit.WebView", (WebView: any) => {
            // Hook WebView.loadUrl (single argument)
            WebView.loadUrl.overload('java.lang.String').implementation = function(url: string) {
                createWebEvent("webview.load_url", {
                    url: url,
                    method: "loadUrl"
                });
                return this.loadUrl(url);
            };

            // Hook WebView.loadUrl (with headers) 
            if (WebView.loadUrl.overloads.length > 1) {
                WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function(url: string, additionalHttpHeaders: any) {
                    createWebEvent("webview.load_url_with_headers", {
                        url: url,
                        headers: additionalHttpHeaders || {},
                        method: "loadUrl"
                    });
                    return this.loadUrl(url, additionalHttpHeaders);
                };
            }

            // Hook WebView.loadData
            WebView.loadData.implementation = function(data: string, mimeType: string, encoding: string) {
                createWebEvent("webview.load_data", {
                    data: data.length > 100 ? data.substring(0, 100) + "..." : data,
                    mime_type: mimeType,
                    encoding: encoding,
                    method: "loadData"
                });
                return this.loadData(data, mimeType, encoding);
            };

            // Hook WebView.postUrl
            if (WebView.postUrl) {
                WebView.postUrl.implementation = function(url: string, postData: any) {
                    createWebEvent("webview.post_url", {
                        url: url,
                        method: "postUrl",
                        data: postData ? `[Binary data: ${postData.length} bytes]` : null
                    });
                    return this.postUrl(url, postData);
                };
            }
        });

        // Hook WebViewClient callbacks
        safeHookClass("android.webkit.WebViewClient", (WebViewClient: any) => {
            WebViewClient.onPageStarted.implementation = function(view: any, url: string, favicon: any) {
                createWebEvent("webview.page_started", {
                    url: url,
                    method: "onPageStarted"
                });
                return this.onPageStarted(view, url, favicon);
            };

            WebViewClient.onPageFinished.implementation = function(view: any, url: string) {
                createWebEvent("webview.page_finished", {
                    url: url,
                    method: "onPageFinished"
                });
                return this.onPageFinished(view, url);
            };

            WebViewClient.shouldOverrideUrlLoading.overload('android.webkit.WebView', 'java.lang.String').implementation = function(view: any, url: string) {
                createWebEvent("webview.url_override", {
                    url: url,
                    method: "shouldOverrideUrlLoading"
                });
                return this.shouldOverrideUrlLoading(view, url);
            };
        });
    });
}

function install_retrofit_hooks() {
    devlog("Installing Retrofit hooks");
    
    Java.perform(() => {
        safeHookClass('retrofit2.OkHttpCall', (OkHttpCall: any) => {
            OkHttpCall.execute.implementation = function() {
                const request = this.request();
                if (request) {
                    createWebEvent("retrofit.request", {
                        url: request.url().toString(),
                        method: request.method()
                    });
                }
                const response = this.execute();
                if (response) {
                    createWebEvent("retrofit.response", {
                        url: request ? request.url().toString() : "unknown",
                        status_code: response.code()
                    });
                }
                return response;
            };
        });

        safeHookClass('retrofit2.Call', (Call: any) => {
            Call.enqueue.implementation = function(callback: any) {
                const request = this.request();
                if (request) {
                    createWebEvent("retrofit.async_request", {
                        url: request.url().toString(),
                        method: request.method()
                    });
                }
                return this.enqueue(callback);
            };
        });
    });
}

function install_volley_hooks() {
    devlog("Installing Volley hooks");
    
    Java.perform(() => {
        safeHookClass('com.android.volley.toolbox.StringRequest', (StringRequest: any) => {
            StringRequest.$init.overload('int', 'java.lang.String', 'com.android.volley.Response$Listener', 'com.android.volley.Response$ErrorListener').implementation = function(method: number, url: string, listener: any, errorListener: any) {
                createWebEvent("volley.string_request", {
                    url: url,
                    method: method === 0 ? "GET" : method === 1 ? "POST" : method === 2 ? "PUT" : method === 3 ? "DELETE" : "UNKNOWN"
                });
                return this.$init(method, url, listener, errorListener);
            };
        });

        safeHookClass('com.android.volley.RequestQueue', (RequestQueue: any) => {
            RequestQueue.add.implementation = function(request: any) {
                if (request.getUrl) {
                    createWebEvent("volley.queue_request", {
                        url: request.getUrl(),
                        method: request.getMethod ? request.getMethod().toString() : "UNKNOWN"
                    });
                }
                return this.add(request);
            };
        });
    });
}

function install_websocket_hooks() {
    devlog("Installing WebSocket hooks");
    
    Java.perform(() => {
        safeHookClass('okhttp3.WebSocket', (WebSocket: any) => {
            WebSocket.send.overload('java.lang.String').implementation = function(text: string) {
                createWebEvent("websocket.send_text", {
                    data: text.length > 200 ? text.substring(0, 200) + "..." : text,
                    method: "send"
                });
                return this.send(text);
            };
        });

        safeHookClass('okhttp3.WebSocketListener', (WebSocketListener: any) => {
            WebSocketListener.onOpen.implementation = function(webSocket: any, response: any) {
                createWebEvent("websocket.opened", {
                    status_code: response.code(),
                    url: response.request().url().toString()
                });
                return this.onOpen(webSocket, response);
            };

            WebSocketListener.onMessage.overload('okhttp3.WebSocket', 'java.lang.String').implementation = function(webSocket: any, text: string) {
                createWebEvent("websocket.message_received", {
                    data: text.length > 200 ? text.substring(0, 200) + "..." : text
                });
                return this.onMessage(webSocket, text);
            };
        });
    });
}

export function install_web_hooks(){
    devlog("\n")
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