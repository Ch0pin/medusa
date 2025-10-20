/**
 * Medusa Android FRIDA Agent
 * Basic template for Android dynamic analysis
 * This file is used as a base template and gets populated by the Medusa framework
 */

'use strict';

// Basic FRIDA agent setup for Android
Java.perform(function() {
    console.log('[*] Medusa Android Agent loaded successfully');
    console.log('[*] Target application: ' + Java.use('android.app.ActivityThread').currentApplication().getApplicationContext().getPackageName());
    
    try {
        // Display application information
        setTimeout(displayAppInfo, 500);
    } catch (err) {
        console.log('[!] Error during initialization: ' + err);
    }
});

// This file will be extended by the Medusa framework with additional modules and hooks
// Do not modify this file directly - use the Medusa framework to add modules and functionality