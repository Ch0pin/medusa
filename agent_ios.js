/**
 * Medusa iOS FRIDA Agent
 * Basic template for iOS dynamic analysis
 * This file is used as a base template and gets populated by the Medusa framework
 */

'use strict';

// Basic FRIDA agent setup for iOS
if (ObjC.available) {
    console.log('[*] Medusa iOS Agent loaded successfully');
    console.log('[*] Objective-C runtime is available');
    
    try {
        // Get application information
        var bundle = ObjC.classes.NSBundle.mainBundle();
        var bundleId = bundle.bundleIdentifier().toString();
        var appName = bundle.objectForInfoDictionaryKey_("CFBundleName");
        
        console.log('[*] Target application: ' + bundleId);
        if (appName) {
            console.log('[*] Application name: ' + appName.toString());
        }
        
        // Display iOS version
        var device = ObjC.classes.UIDevice.currentDevice();
        console.log('[*] iOS Version: ' + device.systemVersion().toString());
        console.log('[*] Device Model: ' + device.model().toString());
        
    } catch (err) {
        console.log('[!] Error during iOS initialization: ' + err);
    }
    
} else {
    console.log('[!] Objective-C runtime is not available - this might not be an iOS app');
}

// This file will be extended by the Medusa framework with additional modules and hooks
// Do not modify this file directly - use the Medusa framework to add modules and functionality