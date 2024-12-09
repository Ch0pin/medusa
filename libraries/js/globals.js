//----------------------begin of globals.js-------------------------------------

'use strict';

var FLAG_SECURE_VALUE = "";
var mode = "";
var methodURL = "";
var requestHeaders = "";
var requestBody = "";
var responseHeaders = "";
var responseBody = "";
var filterKeyWords = ['fragment', 'browser', 'dest', 'url', 'path', 'uri', 'page', 'attachment', 'file', 'dir', 'http', 'navigat', 'link', 'redir', 'web', 'intent', 'html', 'domain', 'af_dp', 'next',
  'target', 'go', 'continue', 'route'
];

const jni_struct_array = ["reserved0","reserved1","reserved2","reserved3","GetVersion","DefineClass","FindClass","FromReflectedMethod","FromReflectedField","ToReflectedMethod","GetSuperclass","IsAssignableFrom","ToReflectedField","Throw","ThrowNew","ExceptionOccurred","ExceptionDescribe","ExceptionClear","FatalError","PushLocalFrame","PopLocalFrame","NewGlobalRef","DeleteGlobalRef","DeleteLocalRef","IsSameObject","NewLocalRef","EnsureLocalCapacity","AllocObject","NewObject","NewObjectV","NewObjectA","GetObjectClass","IsInstanceOf","GetMethodID","CallObjectMethod","CallObjectMethodV","CallObjectMethodA","CallBooleanMethod","CallBooleanMethodV","CallBooleanMethodA","CallByteMethod","CallByteMethodV","CallByteMethodA","CallCharMethod","CallCharMethodV","CallCharMethodA","CallShortMethod","CallShortMethodV","CallShortMethodA","CallIntMethod","CallIntMethodV","CallIntMethodA","CallLongMethod","CallLongMethodV","CallLongMethodA","CallFloatMethod","CallFloatMethodV","CallFloatMethodA","CallDoubleMethod","CallDoubleMethodV","CallDoubleMethodA","CallVoidMethod","CallVoidMethodV","CallVoidMethodA","CallNonvirtualObjectMethod","CallNonvirtualObjectMethodV","CallNonvirtualObjectMethodA","CallNonvirtualBooleanMethod","CallNonvirtualBooleanMethodV","CallNonvirtualBooleanMethodA","CallNonvirtualByteMethod","CallNonvirtualByteMethodV","CallNonvirtualByteMethodA","CallNonvirtualCharMethod","CallNonvirtualCharMethodV","CallNonvirtualCharMethodA","CallNonvirtualShortMethod","CallNonvirtualShortMethodV","CallNonvirtualShortMethodA","CallNonvirtualIntMethod","CallNonvirtualIntMethodV","CallNonvirtualIntMethodA","CallNonvirtualLongMethod","CallNonvirtualLongMethodV","CallNonvirtualLongMethodA","CallNonvirtualFloatMethod","CallNonvirtualFloatMethodV","CallNonvirtualFloatMethodA","CallNonvirtualDoubleMethod","CallNonvirtualDoubleMethodV","CallNonvirtualDoubleMethodA","CallNonvirtualVoidMethod","CallNonvirtualVoidMethodV","CallNonvirtualVoidMethodA","GetFieldID","GetObjectField","GetBooleanField","GetByteField","GetCharField","GetShortField","GetIntField","GetLongField","GetFloatField","GetDoubleField","SetObjectField","SetBooleanField","SetByteField","SetCharField","SetShortField","SetIntField","SetLongField","SetFloatField","SetDoubleField","GetStaticMethodID","CallStaticObjectMethod","CallStaticObjectMethodV","CallStaticObjectMethodA","CallStaticBooleanMethod","CallStaticBooleanMethodV","CallStaticBooleanMethodA","CallStaticByteMethod","CallStaticByteMethodV","CallStaticByteMethodA","CallStaticCharMethod","CallStaticCharMethodV","CallStaticCharMethodA","CallStaticShortMethod","CallStaticShortMethodV","CallStaticShortMethodA","CallStaticIntMethod","CallStaticIntMethodV","CallStaticIntMethodA","CallStaticLongMethod","CallStaticLongMethodV","CallStaticLongMethodA","CallStaticFloatMethod","CallStaticFloatMethodV","CallStaticFloatMethodA","CallStaticDoubleMethod","CallStaticDoubleMethodV","CallStaticDoubleMethodA","CallStaticVoidMethod","CallStaticVoidMethodV","CallStaticVoidMethodA","GetStaticFieldID","GetStaticObjectField","GetStaticBooleanField","GetStaticByteField","GetStaticCharField","GetStaticShortField","GetStaticIntField","GetStaticLongField","GetStaticFloatField","GetStaticDoubleField","SetStaticObjectField","SetStaticBooleanField","SetStaticByteField","SetStaticCharField","SetStaticShortField","SetStaticIntField","SetStaticLongField","SetStaticFloatField","SetStaticDoubleField","NewString","GetStringLength","GetStringChars","ReleaseStringChars","NewStringUTF","GetStringUTFLength","GetStringUTFChars","ReleaseStringUTFChars","GetArrayLength","NewObjectArray","GetObjectArrayElement","SetObjectArrayElement","NewBooleanArray","NewByteArray","NewCharArray","NewShortArray","NewIntArray","NewLongArray","NewFloatArray","NewDoubleArray","GetBooleanArrayElements","GetByteArrayElements","GetCharArrayElements","GetShortArrayElements","GetIntArrayElements","GetLongArrayElements","GetFloatArrayElements","GetDoubleArrayElements","ReleaseBooleanArrayElements","ReleaseByteArrayElements","ReleaseCharArrayElements","ReleaseShortArrayElements","ReleaseIntArrayElements","ReleaseLongArrayElements","ReleaseFloatArrayElements","ReleaseDoubleArrayElements","GetBooleanArrayRegion","GetByteArrayRegion","GetCharArrayRegion","GetShortArrayRegion","GetIntArrayRegion","GetLongArrayRegion","GetFloatArrayRegion","GetDoubleArrayRegion","SetBooleanArrayRegion","SetByteArrayRegion","SetCharArrayRegion","SetShortArrayRegion","SetIntArrayRegion","SetLongArrayRegion","SetFloatArrayRegion","SetDoubleArrayRegion","RegisterNatives","UnregisterNatives","MonitorEnter","MonitorExit","GetJavaVM","GetStringRegion","GetStringUTFRegion","GetPrimitiveArrayCritical","ReleasePrimitiveArrayCritical","GetStringCritical","ReleaseStringCritical","NewWeakGlobalRef","DeleteWeakGlobalRef","ExceptionCheck","NewDirectByteBuffer","GetDirectBufferAddress","GetDirectBufferCapacity","GetObjectRefType"]

  var Color = {
    RESET: "\x1b[39;49;00m", Black: "0;01", Blue: "4;01", Cyan: "6;01", Gray: "7;11", Green: "2;01", Purple: "5;01", Red: "1;01", Yellow: "3;01",
    Light: {
        Black: "0;11", Blue: "4;11", Cyan: "6;11", Gray: "7;01", Green: "2;11", Purple: "5;11", Red: "1;11", Yellow: "3;11"
    }
}

const StyleLogColorset = {
  red: [255, 0, 0],
  green: [0, 255, 0],
  blue: [0, 0, 255],
  yellow: [255, 255, 0],
  magenta: [255, 0, 255],
  cyan: [0, 255, 255],
  white: [255, 255, 255],
  black: [0, 0, 0],
  orange: [255, 165, 0],
  purple: [128, 0, 128],
  pink: [255, 192, 203],
  gold: [255, 215, 0],
  teal: [0, 128, 128],
  lime: [0, 255, 0],
  maroon: [128, 0, 0],
  navy: [0, 0, 128],
  olive: [128, 128, 0],
  silver: [192, 192, 192],
  gray: [128, 128, 128],
  brown: [165, 42, 42],
};

//----------------------end of globals.js-------------------------------------
