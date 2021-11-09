#!/bin/sh


echo '---------------Foreground Activity Monitor -------------------'

var1=$(adb shell dumpsys activity activities | grep mResumedActivity)
var2=$var1
echo $var2 | cut -d ' ' -f 4
while true; do  
    sleep 1
    var1=$(adb shell dumpsys activity activities | grep mResumedActivity)
    if [ "$var1" != "$var2" ]; then
        var2=$var1
        echo $var2 | cut -d ' ' -f 4
    fi

done