//
// Created by zaryab on 4/13/20.
//

#include <jni.h>

#include "secp256k1-cxx.hpp"
#include <string>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief takes hex string and converts to byte array
 * @param env
 * @param str hex string
 * @return byte array
 */
JNIEXPORT jbyteArray JNICALL
Java_com_mediaparkpk_secp256k1android_Secp256k1Wrapper_stringToBytes(JNIEnv *env, jobject obj,
                                                                     jstring str) {
    const char *javaString = env->GetStringUTFChars(str, nullptr);
    auto byteString = Secp256K1::base16Decode(javaString);
    jbyteArray ret = env->NewByteArray(byteString.length());
    env->SetByteArrayRegion(ret, 0, byteString.length(), (const jbyte *) byteString.c_str());

    return ret;
}

JNIEXPORT jstring JNICALL
Java_com_mediaparkpk_secp256k1android_Secp256k1Wrapper_bytesToHex(JNIEnv *env, jobject bytesObj,
                                                                  jbyteArray b) {
    const unsigned char *bytes = (const unsigned char *) env->GetByteArrayElements(b, nullptr);
//    const unsigned char * bytes  = (const unsigned char*)env->GetDirectBufferAddress(b);
    auto byteString = Secp256K1::base16Encode((const char *) bytes);
    return env->NewStringUTF(byteString.c_str());
}

JNIEXPORT jbyteArray JNICALL
Java_com_mediaparkpk_secp256k1android_Secp256k1Wrapper_publicKey(JNIEnv *env,
                                                                 jobject byteObj /* this */,
                                                                 jbyteArray privKeyBytes) {
    auto instance = Secp256K1::getInstance();
    const unsigned char *bytes = (const unsigned char *) env->GetByteArrayElements(privKeyBytes,
                                                                                   nullptr);
    std::vector<uint8_t> priv(32);
    priv.assign(bytes, bytes + 32);
    instance->createPublicKeyFromPriv(priv);

    auto pubKey = instance->uncompressedPublicKey();
    unsigned char *pbKey = pubKey.data();
    auto size = pubKey.size();
    jbyteArray ret = env->NewByteArray(size);
    env->SetByteArrayRegion(ret, 0, size, (jbyte*) pbKey);

    return ret;
}

JNIEXPORT jint JNICALL
Java_com_mediaparkpk_secp256k1android_Secp256k1Wrapper_fingerprint(JNIEnv *env,
                                                                   jobject byteObj /* this */) {
    auto instance = Secp256K1::getInstance();
    uint32_t fp = instance->fingerprint();
    return fp;
}

JNIEXPORT jbyteArray JNICALL
Java_com_mediaparkpk_secp256k1android_Secp256k1Wrapper_privateKey(JNIEnv *env,
                                                                  jobject byteObj /* this */) {
    auto instance = Secp256K1::getInstance();
    std::vector<uint8_t> priv = instance->privateKey();
    unsigned char *pvKey = priv.data();
    auto size = priv.size();
    jbyteArray ret = env->NewByteArray(size);
    env->SetByteArrayRegion(ret, 0, size, (jbyte *) pvKey);
    return ret;
}

JNIEXPORT jbyteArray JNICALL
Java_com_mediaparkpk_secp256k1android_Secp256k1Wrapper_privateKeyTweakAdd(JNIEnv *env,
                                                                  jobject byteObj /* this */,
                                                                  jbyteArray key,
                                                                  jint keySize,
                                                                  jbyteArray tweak,
                                                                  jint tweakSize) {
    auto instance = Secp256K1::getInstance();

    const unsigned char *keyBytes = (const unsigned char *) env->GetByteArrayElements(key,
                                                                                   nullptr);
    const unsigned char *tweakBytes = (const unsigned char *) env->GetByteArrayElements(tweak,
                                                                                   nullptr);
    std::vector<uint8_t> vKey(keyBytes, keyBytes + keySize);
    std::vector<uint8_t> vTweak(tweakBytes, tweakBytes + tweakSize);

    bool result = instance->privKeyTweakAdd(vKey, vTweak);
    if (result) {
        jbyteArray ret = env->NewByteArray(keySize);
        env->SetByteArrayRegion(ret, 0, keySize, (jbyte*)vKey.data());
        return ret;
    }
}


#ifdef __cplusplus
}
#endif
