#!/bin/sh

var1=$(adb shell dumpsys activity activities | grep mResumedActivity)
var2=$var1
echo $var2
while true; do  
    sleep 1
    var1=$(adb shell dumpsys activity activities | grep mResumedActivity)
    if [ "$var1" != "$var2" ]; then
        var2=$var1
        echo $var2
    fi

done