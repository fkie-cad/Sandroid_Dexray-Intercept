import Java_bridge from "frida-java-bridge";
import { devlog } from "./logging.js";  // Passe den Importpfad an deine Struktur an
import type JavaBridge from "frida-java-bridge";
let Java: typeof Java_bridge;

// Robust legacy detection with type check
const javaLegacy = (globalThis as any).Java;

if (javaLegacy && typeof javaLegacy.perform === "function") {
  devlog("[frida-java-bridge] Pre-v17 Frida detected. Using legacy global Java bridge.");
  Java = javaLegacy;
} else {
  devlog("[frida-java-bridge] Frida >=17 detected. Using 'frida-java-bridge' module.");
  Java = Java_bridge;
}




// Simple safe aliases using 'any' to avoid generic constraints
type JavaWrapper = JavaBridge.Wrapper<any>;
type JavaMethod = JavaBridge.Method<any>;

/**
 * Safely attempts to load a Java class without crashing the Frida script.
 * Returns null if the class is not found, allowing hooks to skip gracefully.
 *
 * @param className - The fully qualified Java class name to load
 * @param silent - If true, suppresses the warning log when class is not found
 * @returns The Java class wrapper if found, null otherwise
 */
function safeJavaUse(className: string, silent: boolean = false): JavaWrapper | null {
    try {
        return Java.use(className);
    } catch (e) {
        if (!silent) {
            const errorMsg = e instanceof Error ? e.message : String(e);
            if (errorMsg.includes("ClassNotFoundException")) {
                devlog(`Class '${className}' not found in target app, skipping hook`);
            } else {
                devlog(`Error loading class '${className}': ${errorMsg}`);
            }
        }
        return null;
    }
}

export { Java, JavaWrapper, JavaMethod, safeJavaUse };