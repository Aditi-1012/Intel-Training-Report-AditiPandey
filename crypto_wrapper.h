#ifndef CRYPTO_WRAPPER_H
#define CRYPTO_WRAPPER_H

#include <cstddef>

using BYTE = unsigned char;

class KeypairContext;
class DhContext;

namespace CryptoWrapper {
    bool deriveKey_HKDF_SHA256(const BYTE* salt, size_t saltSize, const BYTE* initialSecret, size_t initialSecretSize, const BYTE* context, size_t contextSize, BYTE* outputKey, size_t outputKeySize);
    bool hmac_SHA256(const BYTE* key, size_t keySize, const BYTE* message, size_t messageSize, BYTE* mac, size_t macSize);
    bool encryptAES_GCM256(const BYTE* key, size_t keySize, const BYTE* plaintext, size_t plaintextSize, const BYTE* aad, size_t aadSize, BYTE* ciphertext, size_t ciphertextBufferSize, size_t* ciphertextSize);
    bool decryptAES_GCM256(const BYTE* key, size_t keySize, const BYTE* ciphertext, size_t ciphertextSize, const BYTE* aad, size_t aadSize, BYTE* plaintext, size_t plaintextBufferSize, size_t* plaintextSize);
    size_t getPlaintextSizeAES_GCM256(size_t ciphertextSize);
    bool signMessageRsa3072Pss(const BYTE* message, size_t messageSize, KeypairContext* privateKeyContext, BYTE* signature, size_t signatureSize);
    bool verifyMessageRsa3072Pss(const BYTE* message, size_t messageSize, KeypairContext* publicKeyContext, const BYTE* signature, size_t signatureSize, bool* signatureIsOK);
    bool readRSAKeyFromFile(const char* filename, const char* password, KeypairContext** keyContext);
    bool getPublicKeyFromCertificate(ByteSmartPtr certBuffer, size_t certBufferSize, KeypairContext** publicKeyContext);
    bool startDh(DhContext** context, BYTE* publicKeyBuffer, size_t publicKeyBufferSize);
    bool getDhSharedSecret(DhContext* context, const BYTE* publicKeyBuffer, size_t publicKeyBufferSize, BYTE* sharedSecretBuffer, size_t sharedSecretBufferSize);
    bool checkCertificate(ByteSmartPtr caCertBuffer, size_t caCertBufferSize, ByteSmartPtr certBuffer, size_t certBufferSize, const char* expectedCN);
    void cleanKeyContext(KeypairContext** keyContext);
    void cleanDhContext(DhContext** context);
}

#endif 
