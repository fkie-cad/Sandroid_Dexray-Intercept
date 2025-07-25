import { am_send, log, devlog } from "../utils/logging.js"
import { getAndroidVersion, arraybuffer2hexstr, copy_file, removeLeadingColon } from "../utils/android_runtime_requests.js"
import { Java } from "../utils/javalib.js"
const PROFILE_HOOKING_TYPE: string = "DEX_STRINGS"


// here we log dynamiclly resolved strings 