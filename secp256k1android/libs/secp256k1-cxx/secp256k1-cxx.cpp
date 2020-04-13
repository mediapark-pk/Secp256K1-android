#include "secp256k1-cxx.hpp"
#include "crypto/ripemd160.h"
#include "crypto/sha2.hpp"

#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>
#include <random>
#include <tuple>
#include <vector>

/**
 * @brief Secp256K1::Secp256K1
 * creates pub/priv key pair
 */
Secp256K1::Secp256K1()
    : ctx(secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))
{
}

Secp256K1::~Secp256K1()
{
    secp256k1_context_destroy(ctx);
}

bool Secp256K1::createPrivateKey()
{
    //get epoch time
    unsigned seed1 = std::chrono::system_clock::now().time_since_epoch().count();

    //generate random number for priv key
    std::seed_seq seed { seed1 };
    std::mt19937_64 eng(seed);
    std::string randString;
    for (int i = 0; i < 10; ++i) {
        randString += eng();
    }

    //generate SHA-256 (our priv key)
    std::vector<uint8_t> out;
    out.resize(32);
    sha256_Raw(reinterpret_cast<const uint8_t*>(randString.c_str()), randString.length(), &out[0]);

    assert(out.size() == 32);

    privKey = std::move(out);
    return verifyKey();
}

/**
 * @brief verifies private key and generates corresponding public key
 * @param privateKey - in hexadecimal
 */
bool Secp256K1::createPublicKeyFromPriv(const std::vector<uint8_t>& privateKey)
{
    privKey = privateKey;
    //verify priv key
    if (!verifyKey()) {
        throw Secp256K1Exception("Unable to create and verify key:  ");
    }

    if (!createPublicKey()) {
        throw Secp256K1Exception("Unable to create publick key");
    }
    return true;
}

/**
 * @brief add tweak and module curve order (key + tweak) mod n
 * @param key
 * @param tweak
 * @return true | false
 */
bool Secp256K1::privKeyTweakAdd(std::vector<uint8_t>& key, const std::vector<uint8_t>& tweak)
{
    bool ret = secp256k1_ec_privkey_tweak_add(ctx, &key[0], tweak.data());
    return ret;
}

std::vector<uint8_t> Secp256K1::uncompressedPublicKey()
{
    secp256k1_pubkey pubkey;
    assert(ctx && "secp256k1_context_verify must be initialized to use CPubKey.");
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, &pubKey[0], pubKey.size())) {
        throw Secp256K1Exception("Unable to parse public key.");
    }
    std::vector<uint8_t> pub(65);
    size_t publen = 65;
    secp256k1_ec_pubkey_serialize(ctx, &pub[0], &publen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    assert(pub.size() == 65);
    return pub;
}

std::vector<uint8_t> Secp256K1::publicKey() const
{
    return pubKey;
}

std::vector<uint8_t> Secp256K1::privateKey() const
{
    return privKey;
}

uint32_t Secp256K1::fingerprint() const
{
    std::vector<uint8_t> final(32);
    sha256_Raw(pubKey.data(), pubKey.size(), &final[0]);
    ripemd160(final.data(), final.size(), &final[0]);
    return ((uint32_t)final[0] << 24) | ((uint32_t)final[1] << 16) | ((uint32_t)final[2] << 8) | ((uint32_t)final[3]);
}

std::string Secp256K1::publicKeyHex() const
{
    return base16Encode(reinterpret_cast<const char*>(pubKey.data()));
}

std::string Secp256K1::privateKeyHex() const
{
    return base16Encode(reinterpret_cast<const char*>(privKey.data()));
}

bool Secp256K1::verifyKey()
{
    return secp256k1_ec_seckey_verify(ctx, privKey.data());
}

bool Secp256K1::createPublicKey(bool compressed)
{
    // Calculate public key.
    secp256k1_pubkey pubkey;
    int ret = secp256k1_ec_pubkey_create(ctx, &pubkey, privKey.data());
    if (ret != 1) {
        return false;
    }

    // Serialize public key.
    size_t outSize = PUBLIC_KEY_SIZE;
    pubKey.resize(outSize);
    secp256k1_ec_pubkey_serialize(
        ctx, pubKey.data(), &outSize, &pubkey,
        compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    pubKey.resize(outSize);

    // Succeed.
    return true;
}

std::tuple<std::vector<uint8_t>, bool> Secp256K1::Sign(
    const uint8_t* hash) const
{
    // Make signature.
    secp256k1_ecdsa_signature sig;
    int ret = secp256k1_ecdsa_sign(ctx, &sig, hash, privKey.data(),
        secp256k1_nonce_function_rfc6979, nullptr);
    if (ret != 1) {
        // Failed to sign.
        return std::make_tuple(std::vector<uint8_t>(), false);
    }

    // Serialize signature.
    std::vector<uint8_t> sigOut(72);
    size_t sigOutSize = 72;
    ret = secp256k1_ecdsa_signature_serialize_der(
        ctx, &sigOut[0], &sigOutSize, &sig);
    if (ret != 1) {
        // Failed to serialize.
        return std::make_tuple(std::vector<uint8_t>(), false);
    }

    // Returns
    sigOut.resize(sigOutSize);
    return std::make_tuple(sigOut, true);
}

/** This function is taken from the libsecp256k1 distribution and implements
 *  DER parsing for ECDSA signatures, while supporting an arbitrary subset of
 *  format violations.
 *
 *  Supported violations include negative integers, excessive padding, garbage
 *  at the end, and overly long length descriptors. This is safe to use in
 *  Bitcoin because since the activation of BIP66, signatures are verified to be
 *  strict DER before being passed to this module, and we know it supports all
 *  violations present in the blockchain before that point.
 */
static int ecdsa_signature_parse_der_lax(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char* input, size_t inputlen)
{
    size_t rpos, rlen, spos, slen;
    size_t pos = 0;
    size_t lenbyte;
    unsigned char tmpsig[64] = { 0 };
    int overflow = 0;

    /* Hack to initialize sig with a correctly-parsed but invalid signature. */
    secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);

    /* Sequence tag byte */
    if (pos == inputlen || input[pos] != 0x30) {
        return 0;
    }
    pos++;

    /* Sequence length bytes */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        pos += lenbyte;
    }

    /* Integer tag byte for R */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for R */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        static_assert(sizeof(size_t) >= 4, "size_t too small");
        if (lenbyte >= 4) {
            return 0;
        }
        rlen = 0;
        while (lenbyte > 0) {
            rlen = (rlen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        rlen = lenbyte;
    }
    if (rlen > inputlen - pos) {
        return 0;
    }
    rpos = pos;
    pos += rlen;

    /* Integer tag byte for S */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for S */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (lenbyte > inputlen - pos) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        static_assert(sizeof(size_t) >= 4, "size_t too small");
        if (lenbyte >= 4) {
            return 0;
        }
        slen = 0;
        while (lenbyte > 0) {
            slen = (slen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        slen = lenbyte;
    }
    if (slen > inputlen - pos) {
        return 0;
    }
    spos = pos;

    /* Ignore leading zeroes in R */
    while (rlen > 0 && input[rpos] == 0) {
        rlen--;
        rpos++;
    }
    /* Copy R value */
    if (rlen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 32 - rlen, input + rpos, rlen);
    }

    /* Ignore leading zeroes in S */
    while (slen > 0 && input[spos] == 0) {
        slen--;
        spos++;
    }
    /* Copy S value */
    if (slen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 64 - slen, input + spos, slen);
    }

    if (!overflow) {
        overflow = !secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    if (overflow) {
        /* Overwrite the result again with a correctly-parsed but invalid
           signature if parsing failed. */
        memset(tmpsig, 0, 64);
        secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    return 1;
}

/**
 * @brief Secp256K1::Verify
 * @param msgHash being verified
 * @param sign input signature (72 bytes)
 * @param pubKey pubKey being used to verify the msg (65 bytes)
 * @return true if success
 */
bool Secp256K1::Verify(const uint8_t* msgHash, const std::vector<uint8_t>& sign, const std::vector<uint8_t>& pubKey)
{
    if (pubKey.size() != PUBLIC_KEY_SIZE) {
        throw Secp256K1Exception("Invalid public key size");
    }
    if (sign.size() != 72) {
        throw Secp256K1Exception("Invalid signature size");
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    // Parse public key.
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pubKey.data(),
            pubKey.size())) {
        return false;
    }

    // Parse signature.
    secp256k1_ecdsa_signature sig;
    if (!ecdsa_signature_parse_der_lax(ctx, &sig, sign.data(), sign.size())) {
        return false;
    }

    secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);
    bool ret = secp256k1_ecdsa_verify(ctx, &sig, msgHash, &pubkey);
    secp256k1_context_destroy(ctx);
    return ret;
}

std::string Secp256K1::base16Decode(const std::string& input)
{
    const auto len = input.length();
    if (len & 1) {
        return "";
    }

    std::string output;
    output.reserve(len / 2);
    for (auto it = input.begin(); it != input.end();) {
        try {
            int hi = hexValue(*it++);
            int lo = hexValue(*it++);
            output.push_back(hi << 4 | lo);
        } catch (const std::invalid_argument& e) {
            throw e;
        }
    }
    return output;
}

int Secp256K1::hexValue(char hex_digit)
{
    switch (hex_digit) {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
        return hex_digit - '0';

    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
        return hex_digit - 'A' + 10;

    case 'a':
    case 'b':
    case 'c':
    case 'd':
    case 'e':
    case 'f':
        return hex_digit - 'a' + 10;
    }
    throw std::invalid_argument("bad hex_digit");
}

std::string Secp256K1::base16Encode(const std::string& input)
{
    static constexpr char hex_digits[] = "0123456789ABCDEF";

    std::string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input) {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

Secp256K1* Secp256K1::instance = nullptr;
Secp256K1* Secp256K1::getInstance()
{
    if (instance == nullptr) {
        instance = new Secp256K1;
    }
    return instance;
}
