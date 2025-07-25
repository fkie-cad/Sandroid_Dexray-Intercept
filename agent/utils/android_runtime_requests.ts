import { log, devlog, am_send } from "./logging.js"
import { Java } from "./javalib.js";

export function getAndroidVersion(){
    var version = 0;

    if(Java.available){
        var version = parseInt(Java.androidVersion);
    }else{
        devlog("Error: cannot get android version");
    }
    //devlog("Android version: " + version);

    return version;
}


export function arraybuffer2hexstr(buffer)
{
    var hexArr = Array.prototype.map.call(
        new Uint8Array(buffer),
        function (bit) {
            return ('00' + bit.toString(16)).slice(-2)
        }
    );
    return hexArr.join(' ');
}


export function java_stack_trace(){
    let traceList: string[] = [];
    Java.perform(function() {
        

        var ThreadDef = Java.use('java.lang.Thread');
        var ThreadObj = ThreadDef.$new();

        function stackTrace() {
            traceList.push("-----------------------------------Start STACK Trace------------------------------");
            var stack = ThreadObj.currentThread().getStackTrace();
            for (var i = 0; i < stack.length; i++) {
                traceList.push(`${i} => `+ stack[i].toString());
               
            }
            traceList.push("-----------------------------------END STACK Trace--------------------------------");
        }


        stackTrace();
    });

    return traceList;
}





export function get_stack_trace_as_string(trace_list : string[]){
    for (let str of trace_list) {
        log(str);
    }
}


export function get_path_from_fd(fd_id: number){
    var path: string = "";

    Java.perform(function() {
        var Paths = Java.use("java.nio.file.Paths");
        var Files = Java.use("java.nio.file.Files");
        var URI = Java.use("java.net.URI");
        var uri_string = "file:///proc/self/fd/"+fd_id;
        var uriObject = URI.$new(uri_string);

    
        var path_obj = Paths.get.overload("java.net.URI").call(Paths,uriObject);
        path = Files.readSymbolicLink(path_obj);
    });


    return path;
}

function get_filename(path: string): string
{
    var filename = "";
    // Find the last '/' and extract everything after it
    let lastSlashIndex: number = path.lastIndexOf('/');
    filename = path.substring(lastSlashIndex + 1);

    return filename;

}

export function removeLeadingColon(input: string): string {
    if (input.startsWith(":")) {
        return input.substring(1);
    }
    return input;
}


export function copy_file(PROFILE_HOOKING_TYPE,source: string, destinationPath: string) {
    var filename: string = get_filename(source)
    var destination: string = destinationPath + "/" + filename;

    Java.perform(function() {
        am_send(PROFILE_HOOKING_TYPE,"creating local copy of unpacked file")
        const File = Java.use('java.io.File');
        const FileInputStream = Java.use("java.io.FileInputStream");
        const FileOutputStream = Java.use("java.io.FileOutputStream");

        //am_send("DEX_UNPACKING","creating local copy of unpacked file0| Fiel="+File)

        //am_send("DEX_UNPACKING","creating local copy of unpacked file0| source="+source)
        var sourceFile = File.$new(source);

        if (sourceFile.exists() && sourceFile.canRead()) {
            //am_send("DEX_UNPACKING","creating local copy of unpacked file1")
            var fis = FileInputStream.$new(sourceFile);
            var inputChannel = fis.getChannel();
            //am_send("DEX_UNPACKING","creating local copy of unpacked file2")

            var destinationFile = File.$new(destination);
            destinationFile.createNewFile();
            var fos = FileOutputStream.$new(destinationFile);
            //am_send("DEX_UNPACKING","creating local copy of unpacked file3")

            var outputChannel = fos.getChannel();
            inputChannel.transferTo(0, inputChannel.size(), outputChannel);
            fis.close();
            fos.close();
            
            am_send(PROFILE_HOOKING_TYPE,"dumped successfully @ " + destination+"\n")
        }else {
            am_send(PROFILE_HOOKING_TYPE,"file has already been deleted")
        }

    });

}