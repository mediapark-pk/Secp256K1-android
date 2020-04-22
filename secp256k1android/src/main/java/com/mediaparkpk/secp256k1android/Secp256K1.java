package com.mediaparkpk.secp256k1android;

public class Secp256K1 {

    public static Secp256k1Wrapper secp256k1Wrapper;

    public static byte[] createPublicKey(byte[] privateKey) {
        return secp256k1Wrapper.createPublicKey(privateKey);
    }

    public static byte[] getPublicKey(boolean isCompressed) {
        return secp256k1Wrapper.publicKey(isCompressed);
    }

    public static byte[] stringToByte(String hex) {
        return secp256k1Wrapper.stringToBytes(hex);
    }

    public static String byteToString(byte[] bytes, int size) {
        return secp256k1Wrapper.bytesToHex(bytes, size);
    }

    public static int getFingurePrint() {
        return secp256k1Wrapper.fingerprint();
    }

    public static byte[] getPrivatekey() {
        return secp256k1Wrapper.privateKey();
    }
    public static byte[] privateKeyTweakAdd(byte[] key, int keySize, byte[] tweak, int tweakSize){
        return secp256k1Wrapper.privateKeyTweakAdd(key, keySize, tweak, tweakSize);
    }
}
