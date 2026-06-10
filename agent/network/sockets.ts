import { log, devlog, am_send } from "../utils/logging.js"
import { get_path_from_fd } from "../utils/android_runtime_requests.js"
import { Where } from "../utils/misc.js"
import { Java } from "../utils/javalib.js"
import { safePerform, safeUse, safeOverload, safeImplementation } from "../utils/safe_java.js"
import { safeAttachExport } from "../utils/safe_native.js"


/**
 * 
 * Some parts are taken from https://github.com/Areizen/Android-Malware-Sandbox/blob/master/frida_scripts/lib/hooks.js
 * https://codeshare.frida.re/@mame82/android-tcp-trace/
 * 
 * must still be extended for UDP
 */

const PROFILE_HOOKING_TYPE: string = "NETWORK_SOCKETS"

function createSocketEvent(eventType: string, data: any): void {
    const event = {
        event_type: eventType,
        timestamp: Date.now(),
        ...data
    };
    am_send(PROFILE_HOOKING_TYPE, JSON.stringify(event));
}

function getStackTrace() {
    const threadDef = Java.use('java.lang.Thread');
    const threadInstance = threadDef.$new();
    return Where(threadInstance.currentThread().getStackTrace());
}

// we need this in order to handle the compiling 
function isTcpEndpointAddress(address: SocketEndpointAddress): address is TcpEndpointAddress {
    return 'ip' in address;
}

function hook_java_socket_communication() {
    // was missing Java.perform entirely, all Java.use calls were unprotected
    safePerform("sockets:hook_java_socket_communication", () => {
        const ServerSocket = safeUse(
            'java.net.ServerSocket',
            "sockets:hook_java_socket_communication"
        );
        const Socket = safeUse(
            'java.net.Socket',
            "sockets:hook_java_socket_communication"
        );
        const LocalServerSocket = safeUse(
            'android.net.LocalServerSocket',
            "sockets:hook_java_socket_communication"
        );
        const DatagramSocket = safeUse(
            'java.net.DatagramSocket',
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
                        var result = original.call(this);
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
                'java.lang.String', 'int'
            );
            if (socketInit) {
                socketInit.implementation = safeImplementation(
                    "sockets:Socket.$init",
                    socketInit,
                    function(original, host, port) {
                        var result = original.call(this, host, port);
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
                'java.net.SocketAddress', 'int'
            );
            if (connectWithTimeout) {
                connectWithTimeout.implementation = safeImplementation(
                    "sockets:Socket.connect[SocketAddress,int]",
                    connectWithTimeout,
                    function(original, p_endpoint, p_timeout) {
                        var result = original.call(this, p_endpoint, p_timeout);
                        createSocketEvent("socket.java.connect", {
                            class: "java.net.Socket",
                            method: "connect",
                            endpoint: p_endpoint.toString(),
                            timeout: p_timeout,
                            stack_trace: getStackTrace()
                        });
                        return result;
                    }
                );
            }

            const connectBasic = safeOverload(
                Socket.connect,
                "sockets:Socket.connect",
                'java.net.SocketAddress'
            );
            if (connectBasic) {
                connectBasic.implementation = safeImplementation(
                    "sockets:Socket.connect[SocketAddress]",
                    connectBasic,
                    function(original, p_endpoint) {
                        var result = original.call(this, p_endpoint);
                        createSocketEvent("socket.java.connect", {
                            class: "java.net.Socket",
                            method: "connect",
                            endpoint: p_endpoint.toString(),
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
                        var result = original.call(this);
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
                'java.net.InetAddress', 'int'
            );
            if (datagramConnect) {
                datagramConnect.implementation = safeImplementation(
                    "sockets:DatagramSocket.connect",
                    datagramConnect,
                    function(original, address, port) {
                        var result = original.call(this, address, port);
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


function hook_bionic_socket_commuication(){
    // TCP/UDP functions in libc.so. Each symbol is now resolved + hooked per-call
    // via safeAttachExport below, so a missing symbol skips only its own hook
    // instead of aborting the whole install (the old Process.getModuleByName threw).
    // Note: "listen" and "accept" were previously resolved here but left unhooked.

    // save sockets
    const socket_list = [];

// Hilfsfunktionen
function swap16(val) {
    return ((val & 0xFF) << 8)
    | ((val >> 8) & 0xFF);
}

function getTimestamp(){
    var seconds = new Date().getTime() / 1000;
    return seconds;
}
/*
function findSocket(sd){
    for(var i in socket_list){
        if(socket_list[i] == sd){
            return i;
        }
    }
    return -1;
} */

function findSocket(sd) {
    for (const [index, socket] of socket_list.entries()) {
        if (socket === sd) {
            return index; // index is guaranteed to be a number
        }
    }
    return -1; // Return -1 if not found, clearly indicating a number is expected
}


function addSocketToList(sd, type){
    for(var i in socket_list){
        if(socket_list[i] == sd){
            return i;
        }
    }
    socket_list.unshift(sd);

    createSocketEvent("socket.native.created", {
        method: "socket",
        socket_descriptor: sd,
        socket_type: type
    });
    
    return -1;
}

// TCP/UDP functions

safeAttachExport("libc.so", "socket", "sockets:socket", {
    onEnter(args) {
        
        this.domain = args[0].toInt32(); //2 für AF_INTET & 22 für AF_INET
        this.type = args[1].toInt32(); //1 für sock_stream, 2 für sock_dgram, 3 für sock_raw
        this.protocol = args[2].toInt32(); // 0 ist standard
    },
    onLeave(retval){
        try{
            var sd = retval.toInt32();
            var sockType = Socket.type(sd);

            // looking for ipv4 or ipv6 sockets
            if(sockType == undefined || sockType == null || sockType === "unix:stream") return;
            if (this.domain == 2 || this.domain == 22){
                //var data1 = {"event_type": "Libc::socket1","method": "socket", "sd": sd, "type": sockType};
                //am_send(PROFILE_HOOKING_TYPE,JSON.stringify(data1));
                
                // add socket to list
                socket_list.unshift(sd);

                // send socket data
                var data = {"event_type": "Libc::socket","method": "socket", "sd": sd, "type": sockType};
                //am_send(PROFILE_HOOKING_TYPE,JSON.stringify(data));
            }
        }catch(error){}
    }
});

safeAttachExport("libc.so", "bind", "sockets:bind", {
    onEnter: function(args) {
        
        this.sd = args[0].toInt32();
        this.addr = args[1];
        this.addrlen = args[2].toInt32();
    },
    onLeave: function(retval){
        // only for known sockets
        if (retval.toInt32() != 0) return;
        
        // looking for tcp or udp sockets
        var sockType = Socket.type(this.sd);
        if(sockType === "udp" || sockType === "udp6" || sockType === "tcp" || sockType === "tcp6"){

            // read local address
            const sockLocal = Socket.localAddress(this.sd)
            var local
            if (isTcpEndpointAddress(sockLocal)) {
                // Now TypeScript knows sockLocal is TcpEndpointAddress, so it allows access to 'ip'
               local  = sockLocal;
            } else {
                // Handle the case where sockLocal is not a TcpEndpointAddress
                return
            }
            //const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : undefined
            
    
            // send bind data
            addSocketToList(this.sd, sockType);
            
            createSocketEvent("socket.native.bind", {
                method: "bind",
                socket_descriptor: this.sd,
                socket_type: sockType,
                local_ip: local.ip,
                local_port: local.port
            });
        }
    }
});

safeAttachExport("libc.so", "connect", "sockets:connect", {
    onEnter: function(args) {
        
        this.sd = args[0].toInt32();
    },
    onLeave: function(retval: any) {
        // check if connect failed
        if (retval.toInt32() == -1) return; 
        
        // read local and remote address
        const sockType = Socket.type(this.sd);
        const sockLocal = Socket.localAddress(this.sd)
        
        var local
        if (isTcpEndpointAddress(sockLocal)) {
                // Now TypeScript knows sockLocal is TcpEndpointAddress, so it allows access to 'ip'
               local  = sockLocal;
        } else {
                // Handle the case where sockLocal is not a TcpEndpointAddress
                am_send(PROFILE_HOOKING_TYPE,JSON.stringify(sockLocal) )
                return
        }


        const sockRemote = Socket.peerAddress(this.sd)
        const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : undefined
        retval |= 0 // Cast retval to 32-bit integer.
        
        
        // if address is not readable
        if(retval != 0 || sockType === "unix:stream" || sockType == null || sockType === undefined || local === undefined || remote === undefined){
            return;
        }
        
        // send connect data
        addSocketToList(this.sd, sockType);
        
        createSocketEvent("socket.native.connect", {
            method: "connect",
            socket_descriptor: this.sd,
            socket_type: sockType,
            local_ip: local.ip,
            local_port: local.port,
            remote_ip: remote.ip,
            remote_port: remote.port
        });
    }
});

safeAttachExport("libc.so", "write", "sockets:write", {
    onEnter: function(args) {
        this.sd = args[0].toInt32();
        this.addr = args[1];
        this.buflen = args[2].toInt32();
    },
    onLeave: function(retval) {
        // check if write failed
        var len = retval.toInt32();
        if(len == -1 || len > this.buflen) return;
        
        // read local and remote address
        const sockType = Socket.type(this.sd);
        const sockLocal = Socket.localAddress(this.sd)
        const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : undefined
        const sockRemote = Socket.peerAddress(this.sd)
        const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : undefined

        // if address is not readable
        if(sockType === "unix:stream" || sockType == null || sockType === undefined || local === undefined || remote === undefined){
            return;
        }

        // read data from buffer
        var buffer;
        var buf = ptr(this.addr);
        if(!buf.isNull()){
            buffer = buf.readByteArray(len);
        }

        // send write data
        addSocketToList(this.sd, sockType);
        
        createSocketEvent("socket.native.write", {
            method: "write",
            socket_descriptor: this.sd,
            socket_type: sockType,
            local_ip: local.ip,
            local_port: local.port,
            remote_ip: remote.ip,
            remote_port: remote.port,
            data_length: len,
            has_buffer: buffer !== undefined
        });
        
        // Send buffer data separately if available
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
        
safeAttachExport("libc.so", "read", "sockets:read", {
    onEnter: function(args) {
        
        this.sd = args[0].toInt32();
        this.addr = args[1];
        this.buflen = args[2].toInt32();
    },
    onLeave: function(retval){
        // check if read failed
        var len = retval.toInt32();
        if(len == -1 || len > this.buflen) return;

        // read local and remote address
        const sockType = Socket.type(this.sd);
        const sockLocal = Socket.localAddress(this.sd)
        const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : undefined
        const sockRemote = Socket.peerAddress(this.sd)
        const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : undefined

        // if address is not readable
        if(sockType === "unix:stream" || sockType == null || sockType === undefined || local === undefined || remote === undefined){
            return;
        }

        // read data from buffer
        var buffer;
        var buf = ptr(this.addr);
        if(!buf.isNull()){
            buffer = buf.readByteArray(len);
        }

        // send read data
        addSocketToList(this.sd, sockType);
        
        createSocketEvent("socket.native.read", {
            method: "read",
            socket_descriptor: this.sd,
            socket_type: sockType,
            local_ip: local.ip,
            local_port: local.port,
            remote_ip: remote.ip,
            remote_port: remote.port,
            data_length: len,
            has_buffer: buffer !== undefined
        });
        
        // Send buffer data separately if available
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

safeAttachExport("libc.so", "sendto", "sockets:sendto", {
    onEnter: function(args) {
        
        this.sd = args[0].toInt32();
        this.addr = args[1];
        this.buflen = args[2].toInt32();
        this.ipAddr = args[4];
    },
    onLeave: function(retval){
        // check if sendto failed
        var len = retval.toInt32();
        if(len == -1 || len > this.buflen) return;
        
        var data;
    
        // read local address
        const sockType = Socket.type(this.sd);
        const sockLocal = Socket.localAddress(this.sd)
        const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : undefined
        
        // if address is not readable
        if(sockType === "unix:stream" || sockType == null || sockType === undefined || local === undefined) return;

        // read data from buffer
        var buffer;
        var buf = ptr(this.addr);
        if(!buf.isNull()){
            buffer = buf.readByteArray(len);
        }
        
        // sendto is like send if ip not provided
        if(this.ipAddr.toInt32() == 0){
        
            // read remote address
            const sockRemote = Socket.peerAddress(this.sd)
            const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : undefined
        
            // if address is not readable
            if(remote === undefined) return;

            //send data 
            addSocketToList(this.sd, sockType);
            
            createSocketEvent("socket.native.sendto", {
                method: "sendto",
                socket_descriptor: this.sd,
                socket_type: sockType,
                local_ip: local.ip,
                local_port: local.port,
                remote_ip: remote.ip,
                remote_port: remote.port,
                data_length: len,
                has_buffer: buffer !== undefined
            });
            
            // Send buffer data separately if available
            if (buffer) {
                am_send(PROFILE_HOOKING_TYPE, JSON.stringify({
                    event_type: "socket.native.sendto_data",
                    timestamp: Date.now(),
                    socket_descriptor: this.sd,
                    data_length: len
                }), buffer);
            }
        } else {

            // read ip addr from memory
            var dest_addr = ptr(this.ipAddr);
            if(dest_addr.isNull() == true) return;
    
            var family = dest_addr.readS16(); 
            if(family == 1){
                // read port
                var port = swap16(dest_addr.add(2).readU16());
                
                // ip address to dotted decimal notation, little endian
                var addr_b0 = dest_addr.add(4).readU8();
                var addr_b1 = dest_addr.add(5).readU8();
                var addr_b2 = dest_addr.add(6).readU8();
                var addr_b3 = dest_addr.add(7).readU8();
                var ip_string = addr_b0 + "." + addr_b1 + "." + addr_b2 + "." + addr_b3;
    
                // send data
                addSocketToList(this.sd, sockType);
                
                createSocketEvent("socket.native.sendto", {
                    method: "sendto",
                    socket_descriptor: this.sd,
                    socket_type: sockType,
                    local_ip: local.ip,
                    local_port: local.port,
                    remote_ip: ip_string,
                    remote_port: port,
                    address_family: family,
                    data_length: len,
                    has_buffer: buffer !== undefined
                });
                
                // Send buffer data separately if available
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

    }
});

safeAttachExport("libc.so", "recvfrom", "sockets:recvfrom", {
    onEnter: function(args) {
        
        this.sd = args[0].toInt32();
        this.addr = args[1];
        this.buflen = args[2].toInt32();
        this.ipAddr = args[4];
    },
    onLeave: function(retval){
        var len = retval.toInt32();
        if(len == -1 || len > this.buflen) return;
        var data;
        
        var buffer;
        var buf = ptr(this.addr);
        if(!buf.isNull()){
            buffer = buf.readByteArray(len);
        }

        // read local address
        const sockType = Socket.type(this.sd);
        const sockLocal = Socket.localAddress(this.sd)
        const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : undefined

        // if address is not readable
        if(sockType === "unix:stream" || sockType == null || sockType === undefined || local === undefined) return;
        
        // recvfrom is like recv if ip not provided
        if(this.ipAddr.toInt32() == 0){
            
            // read remote address
            const sockRemote = Socket.peerAddress(this.sd)
            const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : undefined
    
            // if address is not readable
            if(remote === undefined) return;
            
            // send data
            addSocketToList(this.sd, sockType);
            data = {"event_type": "Libc::recvfrom","method": "recvfrom", "sd": this.sd,  "src_ip": remote.ip,"src_port": remote.port,"dst_ip": local.ip, "dst_port": local.port, "len": len, "type": sockType};
            am_send(PROFILE_HOOKING_TYPE,JSON.stringify(data), buffer);
        } else{
            var src_addr = ptr(this.ipAddr);
            if(src_addr.isNull() == true) return; 
            
            var family = src_addr.readS16(); 
            if(family == 1){
                // read ipv4 address
                var port = swap16(src_addr.add(2).readU16());

                //IP Adresse zu dotted decimal notation, little endian
                var addr_b0 = src_addr.add(4).readU8();
                var addr_b1 = src_addr.add(5).readU8();
                var addr_b2 = src_addr.add(6).readU8();
                var addr_b3 = src_addr.add(7).readU8();
                var ip_string = addr_b0 + "." + addr_b1 + "." + addr_b2 + "." + addr_b3;
                
                // send data
                addSocketToList(this.sd, sockType);
                data = {"event_type": "Libc::recvfrom","method": "recvfrom", "sd" : this.sd,  "len": len, "src_ip": local.ip, "src_port": local.port, "dst_ip": ip_string, "dst_port": port, "dst_family": family, "type": sockType}
                am_send(PROFILE_HOOKING_TYPE,JSON.stringify(data), buffer);
            }
        }
    }
});

safeAttachExport("libc.so", "send", "sockets:send", {
    onEnter: function(args) {
        this.sd = args[0].toInt32();
        this.addr = args[1];
        this.buflen = args[2].toInt32();
    },
    onLeave: function(retval){
        var len = retval.toInt32();
        if(len == -1 || len > this.buflen) return;

        var buffer;
        var buf = ptr(this.addr);
        if(!buf.isNull()){
            buffer = buf.readByteArray(len);
        }

        // read local and remote address
        const sockType = Socket.type(this.sd);
        const sockLocal = Socket.localAddress(this.sd)
        const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : undefined
        const sockRemote = Socket.peerAddress(this.sd)
        const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : undefined

        // if address is not readable
        if(this.sockType === "unix:stream" || sockType == null || sockType === undefined || local === undefined || remote === undefined){
            return;
        }

        // send data
        addSocketToList(this.sd, sockType);
        var data = {"event_type": "Libc::send","method": "send", "sd": this.sd,  "src_ip": local.ip,"src_port": local.port,"dst_ip": remote.ip, "dst_port": remote.port, "len": len, "type": sockType};
        am_send(PROFILE_HOOKING_TYPE,JSON.stringify(data), buffer);
    }
});

safeAttachExport("libc.so", "recv", "sockets:recv", {
    onEnter: function(args) {
        this.sd = args[0].toInt32();
        this.addr = args[1];
        this.buflen = args[2].toInt32();
        
    },
    onLeave: function(retval){
        // check if recv failed
        var len = retval.toInt32();
        if(len == -1 || len > this.buflen) return;
        
        var buffer;
        var buf = ptr(this.addr);
        if(!buf.isNull()){
            buffer = buf.readByteArray(this.len);
        }

        // read local and remote address
        const sockType = Socket.type(this.sd);
        const sockLocal = Socket.localAddress(this.sd)
        const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : undefined
        const sockRemote = Socket.peerAddress(this.sd)
        const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : undefined

        // if address is not readable
        if(sockType === "unix:stream" || sockType == null || sockType === undefined || local === undefined || remote === undefined){
            return;
        }

        // send data
        addSocketToList(this.sd, sockType);
        var data = {"event_type": "Libc::recv","method": "recv", "sd": this.sd,  "src_ip": remote.ip,"src_port": remote.port,"dst_ip": local.ip, "dst_port": local.port, "len": len, "type": sockType};
        am_send(PROFILE_HOOKING_TYPE,JSON.stringify(data), buffer);
    }
});


safeAttachExport("libc.so", "sendmsg", "sockets:sendmsg", {
    onEnter: function(args) {
        
        this.sd = args[0].toInt32();        
        //else {
            // var msg_name = msghdr.readPointer();
            // var msg_namelen = msghdr.add(1).readU32();
            // if(msg_namelen == 0 || msg_name.isNull()){
                //     return;
                // }
                // var ip = msg_name.readByteArray(msg_namelen);
                
                // var msg_control = msghrd.add(10).readPointer();
                // var msg_controllen = msghdr.add(11).readU32();
                // if(msg_iovlen == 0 || msg_iov.isNull()){
            //     console.log("No Message");
            // }
            // if(msg_controllen == 0 || msg_control.isNull()){
            //     console.log("No Controlinfo");
            // }
            //}
    },
    onLeave: function(retval){
        // check if sendmsg failed
        var len = retval.toInt32();
        if(len == -1) return;
        
        // read local and remote address
        const sockType = Socket.type(this.sd);
        const sockLocal = Socket.localAddress(this.sd)
        const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : undefined
        const sockRemote = Socket.peerAddress(this.sd)
        const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : undefined
        
        // if address is not readable
        if(sockType === "unix:stream" || sockType == null || sockType === undefined || local === undefined || remote === undefined){
            return;
        }
        
        // var msghdr = ptr(this.addr);
        // if(msghdr.isNull()){
        //     console.log("Sendmsg failed");
        //     return;
        // }
        
        // var msg_iov = msghdr.add(5).readPointer();
        // var msg_iovlen = msghdr.add(6).readS32();

        // console.log("sendmsg" + msg_iovlen);

        // var buffer;
        // if(!msg_iov.isNull()){
        //     buffer = msg_iov.readByteArray(msg_iovlen);
        // }

        // send data
        addSocketToList(this.sd, sockType);
        var buffer;
        var data = {"event_type": "Libc::sendmsg","method": "sendmsg", "sd": this.sd,  "src_ip": local.ip,"src_port": local.port,"dst_ip": remote.ip, "dst_port": remote.port, "len": len, "type": sockType};
        am_send(PROFILE_HOOKING_TYPE,JSON.stringify(data), buffer);
    }
});

safeAttachExport("libc.so", "recvmsg", "sockets:recvmsg", {
    onEnter: function(args) {
        
        this.sd = args[0].toInt32();
        this.addr = args[1];
    },
    onLeave: function(retval){
        // check if sendmsg failed
        var len = retval.toInt32();
        if(len == -1) return;

        // read local and remote address
        const sockType = Socket.type(this.sd);
        const sockLocal = Socket.localAddress(this.sd)
        const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : undefined
        const sockRemote = Socket.peerAddress(this.sd)
        const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : undefined
        
        // if address is not readable
        if(sockType === "unix:stream" || sockType == null || sockType === undefined || local === undefined || remote === undefined){
            return;
        }
        
        // var msghdr = ptr(this.addr);
        // if(msghdr.isNull()){
        //     console.log("recvmsg failed");
        //     return;
        // }
        
        // var msg_iov = msghdr.add(5).readPointer();
        // var msg_iovlen = msghdr.add(6).readU32();

        // console.log("recvmsg" + msg_iovlen);
        // console.log(msghdr.add(6).readS32())
        
        // if(!msg_iov.isNull()){
        //     var iov_base = msg_iov.readPointer();
        //     var iov_len = msg_iov.add(1).readU32();

        //     console.log(iov_len);
        //     var buffer;
        //     if(!iov_base.isNull()){
        //         buffer = msg_iov.readByteArray(iov_len);
        //     }
        // }

        // send data
        addSocketToList(this.sd, sockType);
        var buffer;
        var data = {"event_type": "Libc::recvmsg","method": "recvmsg", "sd": this.sd,  "src_ip": remote.ip,"src_port": remote.port,"dst_ip": local.ip, "dst_port": local.port, "len": len, "type": sockType};
        am_send(PROFILE_HOOKING_TYPE,JSON.stringify(data));
    }
});



safeAttachExport("libc.so", "close", "sockets:close", {
    onEnter: function(args) {
        this.sd = args[0].toInt32();
    },
    onLeave: function(retval) {
        // check if close failed
        if(retval.toInt32() != 0) return;

        // close only for known sockets
        var socketIndex = findSocket(this.sd);
        if(socketIndex == -1) return;
        socket_list.splice(socketIndex, 1);

        const sockType = Socket.type(this.sd);
        const sockLocal =  Socket.localAddress(this.sd)
        const local = sockLocal && isTcpEndpointAddress(sockLocal) ? sockLocal : undefined
        const sockRemote = Socket.peerAddress(this.sd)
        const remote = sockRemote && isTcpEndpointAddress(sockRemote) ? sockRemote : undefined

        if(sockType === "unix:stream" || sockType == null || sockType === undefined || local === undefined || remote === undefined){
            return;
        }
        
        // send data
        var data = {"event_type": "Libc::close","method":"close", "sd": this.sd, "src_ip": remote.ip,"src_port": remote.port,"dst_ip": local.ip, "dst_port": local.port };
        //am_send("UNTE3RSUCUNG",JSON.stringify(data));
        //am_send(PROFILE_HOOKING_TYPE,JSON.stringify(data));
    }
});

}


export function install_socket_hooks(){
    devlog("\n")
    devlog("install socket hooks");

    try {
        hook_java_socket_communication();
    } catch (error) {
        devlog(`[HOOK] Failed to install Java socket hooks: ${error}`);
    }

    try {
        hook_bionic_socket_commuication();
    } catch (error) {
        devlog(`[HOOK] Failed to install bionic socket hooks: ${error}`);
    }
}