#!/bin/sh

sdk=$(adb  $1 $2 shell getprop ro.build.version.sdk)

if [[ $sdk -gt 30 ]]
then
    subc="topResumedActivity"
    f=3
else
    subc="mResumedActivity"
    f=4
fi
var1=$(adb $1 $2 shell dumpsys activity activities | grep $subc)


var2=$var1
echo $var2 | cut -d ' ' -f $f
while true; do  
    sleep 0.5
    var1=$(adb $1 $2 shell dumpsys activity activities | grep  $subc)
    if [ "$var1" != "$var2" ]; then
        var2=$var1
        echo $var2 | cut -d ' ' -f $f
    fi

done
