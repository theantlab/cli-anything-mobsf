$ANDROID_SDK/build-tools/$1/zipalign -p 4 $6.apk $6-aligned.apk
$ANDROID_SDK/build-tools/$1/apksigner sign --min-sdk-version 24 --ks $2 --ks-key-alias $3 --ks-pass=pass:$4 --key-pass=pass:$5 --out $6-signed.apk $6-aligned.apk
$ANDROID_SDK/build-tools/$1/apksigner verify --min-sdk-version 24 $6-signed.apk
