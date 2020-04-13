#ifndef SECP256K1_CPP_H
#define SECP256K1_CPP_H

#include "libsecp256k1/include/secp256k1.h"

#include <stdexcept>
#include <stdint.h>
#include <vector>

class Secp256K1Exception : public std::runtime_error
{
public:
    Secp256K1Exception(const char* error) noexcept
        : std::runtime_error(error)
    {
    }

    const char* what() const noexcept
    {
        return std::runtime_error::what();
    }
};

class Secp256K1
{
public:
    Secp256K1();
    ~Secp256K1();
    bool createPrivateKey();
    bool createPublicKeyFromPriv(const std::vector<uint8_t>& privateKey);
    bool privKeyTweakAdd(std::vector<uint8_t>& key, const std::vector<uint8_t>& tweak);
    std::vector<uint8_t> uncompressedPublicKey();
    std::vector<uint8_t> publicKey() const;
    std::vector<uint8_t> privateKey() const;
    uint32_t fingerprint() const;
    std::string publicKeyHex() const;
    std::string privateKeyHex() const;
    std::tuple<std::vector<uint8_t>, bool> Sign(const uint8_t* hash) const;
    //    bool Verify(const uint8_t* hash, const std::vector<uint8_t>& sig_in) const;
    static bool Verify(const uint8_t* msgHash, const std::vector<uint8_t>& sig, const std::vector<uint8_t>& pubKey);

    static std::string base16Decode(const std::string& str);
    static std::string base16Encode(const std::string& input);

    static Secp256K1* getInstance();

private:
    secp256k1_context* ctx = NULL;
    std::vector<uint8_t> pubKey;
    std::vector<uint8_t> privKey;

    static constexpr size_t PUBLIC_KEY_SIZE = 65;
    static Secp256K1* instance;

    /** PRIVATE METHODS **/
    bool verifyKey();
    bool createPublicKey(bool compressed = true);
    static int hexValue(char hex_digit);
};

#endif
