//use medusa>dexload /data/local/tmp/stetho.dex


var stethoClassName = 'com.facebook.stetho.Stetho';
const activityThread = Java.use('android.app.ActivityThread');
const app = activityThread.currentApplication();
const context = app.getApplicationContext();


var stetho = Java.use('com.facebook.stetho.Stetho');


    try{
        stetho.initializeWithDefaults(context);
        console.log('Stetho successfully loaded!');
        console.log('Open Chrome at chrome://inspect/#devices');
    }

catch (err) {
    send('Stetho NOT loaded!');
    send(err.toString());
}