# Secp256K1-android

[![](https://jitpack.io/v/mediapark-pk/Secp256K1-android.svg)](https://jitpack.io/#mediapark-pk/Secp256K1-android)

PHP implementation [ECDSA Secp256K1 PHP](https://github.com/furqansiddiqui/ecdsa-php).

Cpp implementation [Secp256K1 Cpp](https://github.com/Waqar144/secp256k1-cxx).


Gradle
------
**Step 1**. Add the JitPack repository to your build file

```gradle
allprojects {
	repositories {
		...
		maven { url 'https://jitpack.io' }
	}
}
```
**Step 2**. Add the dependency
```gradle
dependencies {
    ...
    implementation 'com.github.mediapark-pk:Secp256K1-android:0.2'
}
```
**Methods Exposed and Usage**
-----
* **createPublicKey**
* **publicKey**
* **stringToBytes**
* **bytesToHex**
* **fingerprint**
* **privateKey**
* **privateKeyTweakAdd**




**Releases**
* **0.1**
    * Initial release

License
-------
```
MIT License

Copyright (c) 2020 MediaPark-Pk <admin@mediapark.pk>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
