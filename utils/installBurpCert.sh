#!/bin/sh

if [ $# -lt 1 ]
then
  echo "Usage: $0 devide_id ..."
  exit 1
fi

curl --proxy http://127.0.0.1:8080 -o cacert.der http://burp/cert  \
&& openssl x509 -inform DER -in cacert.der -out cacert.pem \
&& cp cacert.der $(openssl x509 -inform PEM -subject_hash_old -in cacert.pem |head -1).0 \
&& adb -s $1 root \
&& adb -s $1 push $(openssl x509 -inform PEM -subject_hash_old -in cacert.pem |head -1).0 /sdcard/burp.cer \
&& rm $(openssl x509 -inform PEM -subject_hash_old -in cacert.pem |head -1).0 \
&& rm cacert.pem \
&& rm cacert.der \

echo "Certificate is saved as /sdcard/burp.cer"