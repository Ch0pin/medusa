#!/bin/sh

if [ $# -lt 1 ]
then
  echo "Usage: $0 devide_id ..."
  exit 1
fi

curl --proxy http://127.0.0.1:8080 -o burp.der http://burp/cert  \
&& openssl x509 -inform DER -outform PEM -text -in burp.der -out burp.pem \
&& cp burp.der $(openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1).0 \
&& adb -s $1 root \
&& adb -s $1 push $(openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1).0 /sdcard/ \
&& rm $(openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1).0 \
&& rm burp.pem \
&& rm burp.der \

echo "Certificate is saved as /sdcard/burp.cer"