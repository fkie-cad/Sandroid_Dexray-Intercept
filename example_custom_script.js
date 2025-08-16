// Example custom script for dexray-intercept
// This demonstrates the proper way to send messages from custom scripts

// Simple message (will be automatically wrapped by dexray-intercept)
send("Custom script initialized");

// Structured message following dexray-intercept format
send({
    "profileType": "CUSTOM_SCRIPT",
    "profileContent": {
        "script_name": "example_custom_script.js",
        "event_type": "initialization",
        "message": "Script started successfully",
        "data": {
            "version": "1.0",
            "author": "Your Name"
        }
    },
    "timestamp": new Date().toISOString()
});

// Hook Android Toast to demonstrate hooking capability
Java.perform(function() {
    try {
        var Toast = Java.use("android.widget.Toast");
        
        Toast.makeText.overload("android.content.Context", "java.lang.CharSequence", "int").implementation = function(context, text, duration) {
            var result = this.makeText(context, text, duration);
            
            // Send structured message about the Toast
            send({
                "profileType": "CUSTOM_SCRIPT",
                "profileContent": {
                    "hook_type": "android.widget.Toast.makeText",
                    "toast_text": text.toString(),
                    "duration": duration,
                    "timestamp": new Date().toISOString()
                },
                "timestamp": new Date().toISOString()
            });
            
            return result;
        };
        
        send("Successfully hooked Toast.makeText");
        
    } catch (e) {
        send("Error setting up Toast hook: " + e.toString());
    }
});