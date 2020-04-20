package com.mediaparkpk.secp256k1android;

public class Secp256k1Wrapper {
    public native byte[] createPublicKey(byte[] privateKey);

    public native byte[] publicKey(boolean compressed);

    public native byte[] stringToBytes(String s);

    public native String bytesToHex(byte[] b, int size);

    public native int fingerprint();

    public native byte[] privateKey();

    public native byte[] privateKeyTweakAdd(byte[] key, int keySize, byte[] tweak, int tweakSize);

    static {
        System.loadLibrary("secp256k1-wrapper");
    }
}
