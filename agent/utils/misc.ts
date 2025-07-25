//import { Demangler } from 'demangler';
import { Java } from "./javalib.js"

export function isZero(block) {
    var m = /^[0\s]+$/.exec(block);
    return m != null && m.length > 0 && (m[0] == block);
}


export function hexdump_selfmade(buffer, blockSize) {
    blockSize = blockSize || 16;
    var lines = [];
    var hex = "0123456789ABCDEF";
    var prevZero = false,
        ctrZero = 0;
    for (var b = 0; b < buffer.length; b += blockSize) {
        var block = buffer.slice(b, Math.min(b + blockSize, buffer.length));
        var addr = ("0000" + b.toString(16)).slice(-4);
        var codes = block.split('').map(function(ch) {
            var code = ch.charCodeAt(0);
            return " " + hex[(0xF0 & code) >> 4] + hex[0x0F & code];
        }).join("");
        codes += "   ".repeat(blockSize - block.length);
        var chars = block.replace(/[\\x00-\\x1F\\x20\n]/g, '.');
        chars += " ".repeat(blockSize - block.length);
        if (isZero(codes)) {
            ctrZero += blockSize;
            prevZero = true;
        } else {
            if (prevZero) {
                lines.push("\t [" + ctrZero + "] bytes of zeroes");
            }
            lines.push(addr + " " + codes + "  " + chars);
            prevZero = false;
            ctrZero = 0;
        }
    }
    if (prevZero) {
        lines.push("\t [" + ctrZero + "] bytes of zeroes");
    }
    return lines.join("\\n");
}


export function buffer2ArrayBuffer(buffer){
    var result = Java.array('byte', buffer);
                const JString = Java.use('java.lang.String');
                const jstring = JString.$new(result);
                //return str;
    var byteArray = jstring.getBytes("UTF-8");
    const arrayBuffer = new ArrayBuffer(byteArray.length);
    const view = new Uint8Array(arrayBuffer);

    for (let i = 0; i < byteArray.length; i++) {
        view[i] = byteArray[i].valueOf();  // Assuming 'valueOf' gives us the correct byte
    }

    return arrayBuffer;
}


export function byteArray2JString(buffer){
    Java.perform(function () {
        
            try {
                // Convert byte array to string assuming UTF-8 encoding
                var result = Java.array('byte', buffer);
                const JString = Java.use('java.lang.String');
                const str = JString.$new(result);
                //console.log("byteArray2JString:\n"+str)
                /*
                although this is working when we directly print the content to the terminal it doesn't work when we are returning it
                */
                return str; 
            } catch (e) {
                var err_str = 'Error decoding string: ' + e + '\n' + 'B2S-Decoding: ' + b2s(buffer)
                return err_str;
            }
        
    });

}

export function b2s(array) {
    var result = "";
    for (var i = 0; i < array.length; i++) {
        result += String.fromCharCode(modulus(array[i], 256));
    }
    return result;
}

export function modulus(x, n) {
    return ((x % n) + n) % n;
}


export function isPatternPresent(path, patterns) {
    for (var i = 0; i < patterns.length; i++)
        if (path.indexOf(patterns[i]) > -1){
            return true;
        }     
    return false;
}

export function Where(stack){
    var at = "";
    for(var i = 0; i < stack.length; ++i){
        at += stack[i].toString() + "\n";
    }
    return at;
}

export function bytesToHex(bytes) {
    var hex = [];
    for (var i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join('');
}


/*
works only without frida-compile
export function demangleAndExtractFunctionName(lib: string,mangled: string): string {
    try {
        const demangled = new Demangler(mangled);
        
        // Regular expression to extract the function name from the demangled string
        const functionNameMatch = demangled.toString().match(/(\w+::)+\w+/);
        
        if (functionNameMatch) {
            return functionNameMatch[0];
        } else {
            return lib+"Unknown";
        }
    } catch (error) {
        //console.error("Error demangling symbol:", error);
        return lib+"UnknownE";
    }
} */

