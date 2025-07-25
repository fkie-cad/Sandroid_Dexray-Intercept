import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Where } from "../utils/misc.js"

const PROFILE_HOOKING_TYPE: string = "WEB"


function url_init(){
    Java.perform(function () {
        var url = Java.use("java.net.URL");
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        var URLConnection = Java.use('java.net.URLConnection');
        var HttpURLConnectionImpl = Java.use('com.android.okhttp.internal.huc.HttpURLConnectionImpl');

        var threadef = Java.use('java.lang.Thread');
        var threadinstance = threadef.$new();

        url.$init.overload('java.lang.String').implementation = function (var0) {
            var stack = threadinstance.currentThread().getStackTrace()

            if(! var0.startsWith("null")){
                var obj = {"event_type": "Java::net.url", "url" : var0, 'stack': Where(stack), "req_method" : "NULL"};
                am_send(PROFILE_HOOKING_TYPE,JSON.stringify(obj))
            }
            return this.$init(var0);
        };

        var URLConnectionClasses = [HttpURLConnectionImpl, HttpURLConnection, URLConnection];

        URLConnectionClasses.forEach(URLClass => {
            URLClass.connect.overload().implementation = function(){
                var stack = threadinstance.currentThread().getStackTrace()
                var obj = {"event_type": "Java::net.URLConnection", "url" : this.getURL().toString(), 'stack': Where(stack), "req_method" : this.getRequestMethod()};
                am_send(PROFILE_HOOKING_TYPE,JSON.stringify(obj));
                return this.connect();
            }
        });

        url.openConnection.overload().implementation = function(){
            var result = this.openConnection();
            var stack = threadinstance.currentThread().getStackTrace()
            // Cannot retrieve directly the req method, by default GET
            var obj = {"event_type": "Java.net.URLConnection", "url_id": result.hashCode(), "url" : result.getURL().toString(), 'stack': Where(stack), "req_method" : 'NULL'};
            am_send(PROFILE_HOOKING_TYPE,JSON.stringify(obj))
            return result;
        }


        // Hooking java.net.URI methods
        const URI = Java.use('java.net.URI');

        // Hook the URI constructor
        URI.$init.overload('java.lang.String').implementation = function(uriString: string) {
            const result = this.$init(uriString);

            // Send the data
            const json_obj = {
                event_type: "URI Constructor",
                class: "java.net.URI",
                method: "URI(String)",
                event: "Creating new URI",
                uri: uriString
            };
            am_send(PROFILE_HOOKING_TYPE, JSON.stringify(json_obj));

            return result;
        };

        // Hook the toString method
        /*
        URI.toString.overload().implementation = function() {
            const result = this.toString();

            // Send the data
            const json_obj = {
                event_type: "URI toString",
                class: "java.net.URI",
                method: "toString()",
                event: "Converting URI to string",
                uri: result
            };
            am_send(PROFILE_HOOKING_TYPE, JSON.stringify(json_obj));

            return result;
        }; */
    });

}


function hook_http_communication(){
    Java.perform(() => {
        const HttpURLConnection = Java.use("java.net.HttpURLConnection");

        // Hooking into HttpURLConnection
        HttpURLConnection.setRequestMethod.implementation = function(method: string) {
            am_send(PROFILE_HOOKING_TYPE,`HttpURLConnection.setRequestMethod called with method: ${method}`);
            return this.setRequestMethod.apply(this, arguments);
        };

        HttpURLConnection.connect.implementation = function() {
            am_send(PROFILE_HOOKING_TYPE,`HttpURLConnection.connect called`);
            const responseCode = this.getResponseCode();
            am_send(PROFILE_HOOKING_TYPE,`HttpURLConnection response code: ${responseCode}`);
            return this.connect.apply(this, arguments);
        };

        HttpURLConnection.getOutputStream.implementation = function() {
            am_send(PROFILE_HOOKING_TYPE,`HttpURLConnection.getOutputStream called`);
            const outputStream = this.getOutputStream.apply(this, arguments);
            am_send(PROFILE_HOOKING_TYPE,`HttpURLConnection output stream: ${outputStream}`);
            return outputStream;
        };

        HttpURLConnection.getInputStream.implementation = function() {
            am_send(PROFILE_HOOKING_TYPE,`HttpURLConnection.getInputStream called`);
            const inputStream = this.getInputStream.apply(this, arguments);
            am_send(PROFILE_HOOKING_TYPE,`HttpURLConnection input stream: ${inputStream}`);
            return inputStream;
        };
    });

}


function hook_https_commuication(){
    Java.perform(() => {
        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");

        // Hooking into HttpsURLConnection
        HttpsURLConnection.setRequestMethod.implementation = function(method: string) {
            am_send(PROFILE_HOOKING_TYPE,`HttpsURLConnection.setRequestMethod called with method: ${method}`);
            return this.setRequestMethod.apply(this, arguments);
        };

        HttpsURLConnection.connect.implementation = function() {
            am_send(PROFILE_HOOKING_TYPE,`HttpsURLConnection.connect called`);
            const responseCode = this.getResponseCode();
            am_send(PROFILE_HOOKING_TYPE,`HttpsURLConnection response code: ${responseCode}`);
            return this.connect.apply(this, arguments);
        };

        HttpsURLConnection.getOutputStream.implementation = function() {
            am_send(PROFILE_HOOKING_TYPE,`HttpsURLConnection.getOutputStream called`);
            const outputStream = this.getOutputStream.apply(this, arguments);
            am_send(PROFILE_HOOKING_TYPE,`HttpsURLConnection output stream: ${outputStream}`);
            return outputStream;
        };

        HttpsURLConnection.getInputStream.implementation = function() {
            am_send(PROFILE_HOOKING_TYPE,`HttpsURLConnection.getInputStream called`);
            const inputStream = this.getInputStream.apply(this, arguments);
            am_send(PROFILE_HOOKING_TYPE,`HttpsURLConnection input stream: ${inputStream}`);
            return inputStream;
        };

      
    });
    
}


function hook_webview(){
    // taken and adjusted from https://github.com/dpnishant/appmon/blob/master/scripts/Android/WebView/WebView.js
    Java.perform(() => {
        const WebView = Java.use("android.webkit.WebView");
        const WebSettings = Java.use("android.webkit.WebSettings");

        if (WebView.loadUrl) {
            WebView.loadUrl.overloads[0].implementation = function(url: string) {
                let send_data: any = {
                    time: new Date(),
                    txnType: 'WebView',
                    lib: 'android.webkit.WebView',
                    method: 'loadUrl',
                    artifact: []
                };
                let data: any = {
                    name: "URL",
                    value: url,
                    argSeq: 0
                };
                send_data.artifact.push(data);
                am_send(PROFILE_HOOKING_TYPE,JSON.stringify(send_data));
                return this.loadUrl.overloads[0].apply(this, arguments);
            };

            WebView.loadUrl.overloads[1].implementation = function(url: string, additionalHttpHeaders: any) {
                let send_data: any = {
                    time: new Date(),
                    txnType: 'WebView',
                    lib: 'android.webkit.WebView',
                    method: 'loadUrl',
                    artifact: []
                };
                let dataUrl: any = {
                    name: "URL",
                    value: url,
                    argSeq: 0
                };
                send_data.artifact.push(dataUrl);
                let dataHeaders: any = {
                    name: "Additional Headers",
                    value: additionalHttpHeaders,
                    argSeq: 0
                };
                send_data.artifact.push(dataHeaders);
                am_send(PROFILE_HOOKING_TYPE,JSON.stringify(send_data));
                return this.loadUrl.overloads[1].apply(this, arguments);
            };
        }

        if (WebView.loadData) {
            WebView.loadData.implementation = function(data: string, mimeType: string, encoding: string) {
                let send_data: any = {
                    time: new Date(),
                    txnType: 'WebView',
                    lib: 'android.webkit.WebView',
                    method: 'loadData',
                    artifact: []
                };
                let dataContent: any = {
                    name: "Data",
                    value: data,
                    argSeq: 0
                };
                send_data.artifact.push(dataContent);
                let dataMimeType: any = {
                    name: "MIME Type",
                    value: mimeType,
                    argSeq: 0
                };
                send_data.artifact.push(dataMimeType);
                let dataEncoding: any = {
                    name: "Encoding",
                    value: encoding,
                    argSeq: 0
                };
                send_data.artifact.push(dataEncoding);
                am_send(PROFILE_HOOKING_TYPE,JSON.stringify(send_data));
                return this.loadData.apply(this, arguments);
            };
        }

        if (WebView.loadDataWithBaseURL) {
            WebView.loadDataWithBaseURL.implementation = function(baseUrl: string, data: string, mimeType: string, encoding: string, historyUrl: string) {
                let send_data: any = {
                    time: new Date(),
                    txnType: 'WebView',
                    lib: 'android.webkit.WebView',
                    method: 'loadDataWithBaseURL',
                    artifact: []
                };
                let dataBaseUrl: any = {
                    name: "Base URL",
                    value: baseUrl,
                    argSeq: 0
                };
                send_data.artifact.push(dataBaseUrl);
                let dataContent: any = {
                    name: "Data",
                    value: data,
                    argSeq: 0
                };
                send_data.artifact.push(dataContent);
                let dataMimeType: any = {
                    name: "MIME Type",
                    value: mimeType,
                    argSeq: 0
                };
                send_data.artifact.push(dataMimeType);
                let dataEncoding: any = {
                    name: "Encoding",
                    value: encoding,
                    argSeq: 0
                };
                send_data.artifact.push(dataEncoding);
                let dataHistoryUrl: any = {
                    name: "History URL",
                    value: historyUrl,
                    argSeq: 0
                };
                send_data.artifact.push(dataHistoryUrl);
                am_send(PROFILE_HOOKING_TYPE,JSON.stringify(send_data));
                return this.loadDataWithBaseURL.apply(this, arguments);
            };
        }

        if (WebView.addJavascriptInterface) {
            WebView.addJavascriptInterface.implementation = function(object: any, name: string) {
                let send_data: any = {
                    time: new Date(),
                    txnType: 'WebView',
                    lib: 'android.webkit.WebView',
                    method: 'addJavascriptInterface',
                    artifact: []
                };
                let dataObject: any = {
                    name: "Object",
                    value: object,
                    argSeq: 0
                };
                send_data.artifact.push(dataObject);
                let dataName: any = {
                    name: "Name",
                    value: name,
                    argSeq: 0
                };
                send_data.artifact.push(dataName);
                am_send(PROFILE_HOOKING_TYPE,JSON.stringify(send_data));
                return this.addJavascriptInterface.apply(this, arguments);
            };
        }

        if (WebView.evaluateJavascript) {
            WebView.evaluateJavascript.implementation = function(script: string, resultCallback: any) {
                let send_data: any = {
                    time: new Date(),
                    txnType: 'WebView',
                    lib: 'android.webkit.WebView',
                    method: 'evaluateJavascript',
                    artifact: []
                };
                let dataScript: any = {
                    name: "Script",
                    value: script,
                    argSeq: 0
                };
                send_data.artifact.push(dataScript);
                am_send(PROFILE_HOOKING_TYPE,JSON.stringify(send_data));
                return this.evaluateJavascript.apply(this, arguments);
            };
        }

        if (WebView.postUrl) {
            WebView.postUrl.implementation = function(url: string, postData: any) {
                let send_data: any = {
                    time: new Date(),
                    txnType: 'WebView',
                    lib: 'android.webkit.WebView',
                    method: 'postUrl',
                    artifact: []
                };
                let dataUrl: any = {
                    name: "URL",
                    value: url,
                    argSeq: 0
                };
                send_data.artifact.push(dataUrl);
                let dataPostData: any = {
                    name: "POST Data",
                    value: JSON.stringify(postData),
                    argSeq: 0
                };
                send_data.artifact.push(dataPostData);
                am_send(PROFILE_HOOKING_TYPE,JSON.stringify(send_data));
                return this.postUrl.apply(this, arguments);
            };
        }

        if (WebView.postWebMessage) {
            WebView.postWebMessage.implementation = function(message: any, targetOrigin: string) {
                let send_data: any = {
                    time: new Date(),
                    txnType: 'WebView',
                    lib: 'android.webkit.WebView',
                    method: 'postWebMessage',
                    artifact: []
                };
                let dataMessage: any = {
                    name: "Message",
                    value: JSON.stringify(message.getData()),
                    argSeq: 0
                };
                send_data.artifact.push(dataMessage);
                let dataTargetOrigin: any = {
                    name: "Target Origin",
                    value: targetOrigin,
                    argSeq: 0
                };
                send_data.artifact.push(dataTargetOrigin);
                am_send(PROFILE_HOOKING_TYPE,JSON.stringify(send_data));
                return this.postWebMessage.apply(this, arguments);
            };
        }

        if (WebView.savePassword) {
            WebView.savePassword.implementation = function(host: string, username: string, password: string) {
                let send_data: any = {
                    time: new Date(),
                    txnType: 'WebView',
                    lib: 'android.webkit.WebView',
                    method: 'savePassword',
                    artifact: []
                };
                let dataHost: any = {
                    name: "Host",
                    value: host,
                    argSeq: 0
                };
                send_data.artifact.push(dataHost);
                let dataUsername: any = {
                    name: "Username",
                    value: username,
                    argSeq: 0
                };
                send_data.artifact.push(dataUsername);
                let dataPassword: any = {
                    name: "Password",
                    value: password,
                    argSeq: 0
                };
                send_data.artifact.push(dataPassword);
                am_send(PROFILE_HOOKING_TYPE,JSON.stringify(send_data));
                return this.savePassword.apply(this, arguments);
            };
        }

        if (WebView.setHttpAuthUsernamePassword) {
            WebView.setHttpAuthUsernamePassword.implementation = function(host: string, realm: string, username: string, password: string) {
                let send_data: any = {
                    time: new Date(),
                    txnType: 'WebView',
                    lib: 'android.webkit.WebView',
                    method: 'setHttpAuthUsernamePassword',
                    artifact: []
                };
                let dataHost: any = {
                    name: "Host",
                    value: host,
                    argSeq: 0
                };
                send_data.artifact.push(dataHost);
                let dataRealm: any = {
                    name: "Realm",
                    value: realm,
                    argSeq: 0
                };
                send_data.artifact.push(dataRealm);
                let dataUsername: any = {
                    name: "Username",
                    value: username,
                    argSeq: 0
                };
                send_data.artifact.push(dataUsername);
                let dataPassword: any = {
                    name: "Password",
                    value: password,
                    argSeq: 0
                };
                send_data.artifact.push(dataPassword);
                am_send(PROFILE_HOOKING_TYPE,JSON.stringify(send_data));
                return this.setHttpAuthUsernamePassword.apply(this, arguments);
            };
        }

        if (WebView.getHttpAuthUsernamePassword) {
            WebView.getHttpAuthUsernamePassword.implementation = function(host: string, realm: string) {
                const credentials = this.getHttpAuthUsernamePassword.apply(this, arguments);
                let send_data: any = {
                    time: new Date(),
                    txnType: 'WebView',
                    lib: 'android.webkit.WebView',
                    method: 'getHttpAuthUsernamePassword',
                    artifact: []
                };
                let dataHost: any = {
                    name: "Host",
                    value: host,
                    argSeq: 0
                };
                send_data.artifact.push(dataHost);
                let dataRealm: any = {
                    name: "Realm",
                    value: realm,
                    argSeq: 0
                };
                send_data.artifact.push(dataRealm);
                let dataCredentials: any = {
                    name: "Credentials",
                    value: credentials,
                    argSeq: 0
                };
                send_data.artifact.push(dataCredentials);
                am_send(PROFILE_HOOKING_TYPE,JSON.stringify(send_data));
                return credentials;
            };
        }
    });
}

function hook_okHTTP(){
    Java.perform(function () {
        try {
            let OkHttpClient = Java.use('okhttp3.OkHttpClient');
            OkHttpClient.newCall.overload('okhttp3.Request').implementation = function (request) {
                let logData = {
                    "event_type": '[Request - OkHttpClient]',
                    url: request.url().toString(),
                    method: request.method(),
                    headers: {},
                    body: null
                };
                let headers = request.headers();
                let headerNames = headers.names().toArray();
                for (let i = 0; i < headerNames.length; i++) {
                    logData.headers[headerNames[i]] = headers.get(headerNames[i]);
                }
                if (request.body()) {
                    logData.body = request.body().toString();
                }

                am_send(PROFILE_HOOKING_TYPE, JSON.stringify(logData, null, 2));
                let response = this.newCall(request).execute();
                let responseData = {
                    "event_type": '[Response - OkHttpClient]',
                    statusCode: response.code(),
                    headers: {},
                    body: response.body().string()
                };
                let responseHeaders = response.headers();
                let responseHeaderNames = responseHeaders.names().toArray();
                for (let i = 0; i < responseHeaderNames.length; i++) {
                    responseData.headers[responseHeaderNames[i]] = responseHeaders.get(responseHeaderNames[i]);
                }
    
                
                am_send(PROFILE_HOOKING_TYPE, JSON.stringify(responseData, null, 4));
                return this.newCall(request);
            };

            let OkHttpClient_old = Java.use('okhttp.OkHttpClient');
            OkHttpClient_old.newCall.overload('okhttp.Request').implementation = function (request) {
                let logData = {
                    "event_type": '[Request - OkHttpClient]',
                    url: request.url().toString(),
                    method: request.method(),
                    headers: {},
                    body: null
                };
                let headers = request.headers();
                let headerNames = headers.names().toArray();
                for (let i = 0; i < headerNames.length; i++) {
                    logData.headers[headerNames[i]] = headers.get(headerNames[i]);
                }
                if (request.body()) {
                    logData.body = request.body().toString();
                }

                am_send(PROFILE_HOOKING_TYPE, JSON.stringify(logData, null, 2));
                let response = this.newCall(request).execute();
                let responseData = {
                    "event_type": '[Response - OkHttpClient]',
                    statusCode: response.code(),
                    headers: {},
                    body: response.body().string()
                };
                let responseHeaders = response.headers();
                let responseHeaderNames = responseHeaders.names().toArray();
                for (let i = 0; i < responseHeaderNames.length; i++) {
                    responseData.headers[responseHeaderNames[i]] = responseHeaders.get(responseHeaderNames[i]);
                }
    
                
                am_send(PROFILE_HOOKING_TYPE, JSON.stringify(responseData, null, 4));
                return this.newCall(request);
            };



            const HttpURLConnectionImpl = Java.use("com.android.okhttp.internal.huc.HttpURLConnectionImpl");
             // Hook HttpURLConnection.setRequestProperty to get various request headers and properties
            HttpURLConnectionImpl.setRequestProperty.implementation = function (str1: string, str2: string) {
                const result = this.setRequestProperty(str1, str2);
                am_send(PROFILE_HOOKING_TYPE,"HttpURLConnectionImpl.setRequestProperty result, str1, str2 =>"+ result+  "("+ str1 +","+ str2+")");
                return result;
            };

            // Hook HttpURLConnection.setRequestMethod to get the request method
            HttpURLConnectionImpl.setRequestMethod.implementation = function (str1: string) {
                const result = this.setRequestMethod(str1);
                am_send(PROFILE_HOOKING_TYPE,"HttpURLConnectionImpl.setRequestMethod result, str1 =>"+ result + "("+ str1+")");
                return result;
            };
    

        } catch (error) {
            //console.error('OkHttpClient not found or there was an issue hooking it.');
        }
    });

}



export function install_web_hooks(){
    devlog("\n")
    devlog("install web hooks");
    url_init();
    hook_http_communication();
    hook_https_commuication();
    hook_okHTTP();
    hook_webview();

}