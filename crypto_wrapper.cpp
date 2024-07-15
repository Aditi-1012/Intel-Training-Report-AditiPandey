#include "crypto_wrapper.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <cstring>
#include <memory>

bool CryptoWrapper::deriveKey_HKDF_SHA256(const BYTE* salt, size_t saltSize, const BYTE* initialSecret, size_t initialSecretSize, const BYTE* context, size_t contextSize, BYTE* outputKey, size_t outputKeySize) {
    return EVP_PKEY_derive(salt, initialSecret, outputKey);
}

bool CryptoWrapper::hmac_SHA256(const BYTE* key, size_t keySize, const BYTE* message, size_t messageSize, BYTE* mac, size_t macSize) {
    unsigned int len = 0;
    HMAC_CTX* ctx = HMAC_CTX_new();
    if (!ctx) return false;

    if (HMAC_Init_ex(ctx, key, keySize, EVP_sha256(), NULL) != 1 ||
        HMAC_Update(ctx, message, messageSize) != 1 ||
        HMAC_Final(ctx, mac, &len) != 1) {
        HMAC_CTX_free(ctx);
        return false;
    }
    
    HMAC_CTX_free(ctx);
    return len == macSize;
}

bool CryptoWrapper::encryptAES_GCM256(const BYTE* key, size_t keySize, const BYTE* plaintext, size_t plaintextSize, const BYTE* aad, size_t aadSize, BYTE* ciphertext, size_t ciphertextBufferSize, size_t* ciphertextSize) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, NULL) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, (int*)ciphertextSize, aad, aadSize) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext, (int*)ciphertextSize, plaintext, plaintextSize) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext + *ciphertextSize, (int*)ciphertextSize) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool CryptoWrapper::decryptAES_GCM256(const BYTE* key, size_t keySize, const BYTE* ciphertext, size_t ciphertextSize, const BYTE* aad, size_t aadSize, BYTE* plaintext, size_t plaintextBufferSize, size_t* plaintextSize) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, NULL) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, (int*)plaintextSize, aad, aadSize) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext, (int*)plaintextSize, ciphertext, ciphertextSize) != 1 ||
        EVP_DecryptFinal_ex(ctx, plaintext + *plaintextSize, (int*)plaintextSize) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

size_t CryptoWrapper::getPlaintextSizeAES_GCM256(size_t ciphertextSize) {
    return ciphertextSize; 
}

bool CryptoWrapper::signMessageRsa3072Pss(const BYTE* message, size_t messageSize, KeypairContext* privateKeyContext, BYTE* signature, size_t signatureSize) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, privateKeyContext) != 1 ||
        EVP_DigestSign(ctx, signature, &signatureSize, message, messageSize) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    EVP_MD_CTX_free(ctx);
    return true;
}

bool CryptoWrapper::verifyMessageRsa3072Pss(const BYTE* message, size_t messageSize, KeypairContext* publicKeyContext, const BYTE* signature, size_t signatureSize, bool* signatureIsOK) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, publicKeyContext) != 1 ||
        EVP_DigestVerify(ctx, signature, signatureSize, message, messageSize) != 1) {
        *signatureIsOK = false;
    } else {
        *signatureIsOK = true;
    }

    EVP_MD_CTX_free(ctx);
    return true;
}



