package com.mediaparkpk.secp256k1app;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

import com.mediaparkpk.secp256k1android.Secp256k1Wrapper;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Secp256k1Wrapper secp256k1Wrapper = new Secp256k1Wrapper();
        byte[] b = secp256k1Wrapper.stringToBytes("aa9ce7ec21a5655d5b54ac57fa2f0b37d0606967679eef32eff16cc84be8fa9c");
        byte[] pb = secp256k1Wrapper.publicKey(b);
        String s = secp256k1Wrapper.bytesToHex(pb);
        assert(s == "");
//        secp256k1Wrapper.publicKey();

    }
}
