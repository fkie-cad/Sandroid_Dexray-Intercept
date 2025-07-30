import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Where } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"

const PROFILE_HOOKING_TYPE: string = "WEB"

interface WebEvent {
    event_type: string;
    timestamp: number;
    url?: string;
    method?: string;
    headers?: Record<string, any>;
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
        const URL = Java.use("java.net.URL");
        const HttpURLConnection = Java.use('java.net.HttpURLConnection');
        const URLConnection = Java.use('java.net.URLConnection');
        const HttpURLConnectionImpl = Java.use('com.android.okhttp.internal.huc.HttpURLConnectionImpl');
        const URI = Java.use('java.net.URI');
        const threadDef = Java.use('java.lang.Thread');
        const threadInstance = threadDef.$new();

        // Hook URL constructor
        URL.$init.overload('java.lang.String').implementation = function (urlString: string) {
            const result = this.$init(urlString);
            
            if (!urlString.startsWith("null")) {
                const stack = threadInstance.currentThread().getStackTrace();
                createWebEvent("url.creation", {
                    url: urlString,
                    stack_trace: Where(stack),
                    req_method: "GET"
                });
            }
            return result;
        };

        // Hook URL connection methods
        const connectionClasses = [HttpURLConnectionImpl, HttpURLConnection, URLConnection];
        connectionClasses.forEach(ConnectionClass => {
            try {
                ConnectionClass.connect.overload().implementation = function() {
                    const stack = threadInstance.currentThread().getStackTrace();
                    createWebEvent("url.connection", {
                        url: this.getURL().toString(),
                        stack_trace: Where(stack),
                        req_method: this.getRequestMethod ? this.getRequestMethod() : "GET"
                    });
                    return this.connect();
                };
            } catch (e) {
                devlog(`Could not hook ${ConnectionClass.$className}.connect: ${e}`);
            }
        });

        // Hook URL openConnection
        URL.openConnection.overload().implementation = function() {
            const result = this.openConnection();
            const stack = threadInstance.currentThread().getStackTrace();
            
            createWebEvent("url.open_connection", {
                url: result.getURL().toString(),
                stack_trace: Where(stack),
                req_method: "GET"
            });
            return result;
        };

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
}


function install_http_hooks() {
    devlog("Installing HTTP communication hooks");
    
    Java.perform(() => {
        const HttpURLConnection = Java.use("java.net.HttpURLConnection");

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
            createWebEvent("http.input_stream", {
                url: this.getURL ? this.getURL().toString() : "unknown",
                method: this.getRequestMethod ? this.getRequestMethod() : "GET"
            });
            return inputStream;
        };
    });
}


function install_https_hooks() {
    devlog("Installing HTTPS communication hooks");
    
    Java.perform(() => {
        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");

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

        // Hook HTTPS output stream
        HttpsURLConnection.getOutputStream.implementation = function() {
            const outputStream = this.getOutputStream();
            createWebEvent("https.output_stream", {
                url: this.getURL ? this.getURL().toString() : "unknown",
                method: this.getRequestMethod ? this.getRequestMethod() : "GET"
            });
            return outputStream;
        };

        // Hook HTTPS input stream
        HttpsURLConnection.getInputStream.implementation = function() {
            const inputStream = this.getInputStream();
            createWebEvent("https.input_stream", {
                url: this.getURL ? this.getURL().toString() : "unknown",
                method: this.getRequestMethod ? this.getRequestMethod() : "GET"
            });
            return inputStream;
        };
    });
}


function install_webview_hooks(){
    devlog("Installing WebView hooks");
    
    Java.perform(() => {
        const WebView = Java.use("android.webkit.WebView");

        // Hook WebView.loadUrl (single argument)
        if (WebView.loadUrl && WebView.loadUrl.overloads.length > 0) {
            WebView.loadUrl.overloads[0].implementation = function(url: string) {
                createWebEvent("webview.load_url", {
                    url: url,
                    method: "loadUrl"
                });
                return this.loadUrl(url);
            };

            // Hook WebView.loadUrl (with headers)
            if (WebView.loadUrl.overloads.length > 1) {
                WebView.loadUrl.overloads[1].implementation = function(url: string, additionalHttpHeaders: any) {
                    createWebEvent("webview.load_url_with_headers", {
                        url: url,
                        headers: additionalHttpHeaders || {},
                        method: "loadUrl"
                    });
                    return this.loadUrl(url, additionalHttpHeaders);
                };
            }
        }

        // Hook WebView.loadData
        if (WebView.loadData) {
            WebView.loadData.implementation = function(data: string, mimeType: string, encoding: string) {
                createWebEvent("webview.load_data", {
                    data: data.length > 100 ? data.substring(0, 100) + "..." : data,
                    mime_type: mimeType,
                    encoding: encoding,
                    method: "loadData"
                });
                return this.loadData(data, mimeType, encoding);
            };
        }

        // Hook WebView.loadDataWithBaseURL
        if (WebView.loadDataWithBaseURL) {
            WebView.loadDataWithBaseURL.implementation = function(baseUrl: string, data: string, mimeType: string, encoding: string, historyUrl: string) {
                createWebEvent("webview.load_data_with_base_url", {
                    url: baseUrl,
                    data: data.length > 100 ? data.substring(0, 100) + "..." : data,
                    mime_type: mimeType,
                    encoding: encoding,
                    method: "loadDataWithBaseURL"
                });
                return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
            };
        }

        // Hook WebView.addJavascriptInterface
        if (WebView.addJavascriptInterface) {
            WebView.addJavascriptInterface.implementation = function(object: any, name: string) {
                createWebEvent("webview.add_javascript_interface", {
                    method: "addJavascriptInterface",
                    data: `Interface name: ${name}`
                });
                return this.addJavascriptInterface(object, name);
            };
        }

        // Hook WebView.evaluateJavascript
        if (WebView.evaluateJavascript) {
            WebView.evaluateJavascript.implementation = function(script: string, resultCallback: any) {
                createWebEvent("webview.evaluate_javascript", {
                    method: "evaluateJavascript",
                    data: script.length > 100 ? script.substring(0, 100) + "..." : script
                });
                return this.evaluateJavascript(script, resultCallback);
            };
        }

        // Hook WebView.postUrl
        if (WebView.postUrl) {
            WebView.postUrl.implementation = function(url: string, postData: any) {
                createWebEvent("webview.post_url", {
                    url: url,
                    method: "postUrl",
                    data: postData ? JSON.stringify(postData) : null
                });
                return this.postUrl(url, postData);
            };
        }
    });
}

function install_okhttp_hooks(){
    devlog("Installing OkHTTP hooks");
    
    Java.perform(() => {
        try {
            // Hook OkHttp3 client
            const OkHttpClient = Java.use('okhttp3.OkHttpClient');
            OkHttpClient.newCall.overload('okhttp3.Request').implementation = function (request) {
                const headers: Record<string, string> = {};
                const requestHeaders = request.headers();
                const headerNames = requestHeaders.names().toArray();
                
                for (let i = 0; i < headerNames.length; i++) {
                    headers[headerNames[i]] = requestHeaders.get(headerNames[i]);
                }

                createWebEvent("okhttp.request", {
                    url: request.url().toString(),
                    method: request.method(),
                    headers: headers,
                    body: request.body() ? request.body().toString() : null
                });

                const call = this.newCall(request);
                try {
                    const response = call.execute();
                    const responseHeaders: Record<string, string> = {};
                    const respHeaders = response.headers();
                    const respHeaderNames = respHeaders.names().toArray();
                    
                    for (let i = 0; i < respHeaderNames.length; i++) {
                        responseHeaders[respHeaderNames[i]] = respHeaders.get(respHeaderNames[i]);
                    }

                    createWebEvent("okhttp.response", {
                        url: request.url().toString(),
                        status_code: response.code(),
                        headers: responseHeaders,
                        body: response.body() ? response.body().string() : null
                    });
                } catch (e) {
                    devlog(`OkHttp response processing error: ${e}`);
                }
                
                return call;
            };

            // Hook legacy OkHttp client
            try {
                const OkHttpClientOld = Java.use('okhttp.OkHttpClient');
                OkHttpClientOld.newCall.overload('okhttp.Request').implementation = function (request) {
                    createWebEvent("okhttp_old.request", {
                        url: request.url().toString(),
                        method: request.method()
                    });
                    return this.newCall(request);
                };
            } catch (e) {
                devlog("Legacy OkHttpClient not found");
            }

            // Hook HttpURLConnectionImpl from OkHttp
            try {
                const HttpURLConnectionImpl = Java.use("com.android.okhttp.internal.huc.HttpURLConnectionImpl");
                
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
            } catch (e) {
                devlog("HttpURLConnectionImpl not found");
            }

        } catch (error) {
            devlog(`OkHttpClient hook error: ${error}`);
        }
    });

}



export function install_web_hooks(){
    devlog("\n")
    devlog("Installing web hooks");
    
    install_url_hooks();
    install_http_hooks();
    install_https_hooks();
    install_okhttp_hooks();
    install_webview_hooks();
}