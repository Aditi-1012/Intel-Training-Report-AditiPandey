KeypairContext* keypair_context;

if (readRSAKeyFromFile("private_key.pem", "password", &keypair_context)) {
    printf("RSA key loaded successfully.\n");
} else {
    printf("Failed to load RSA key.\n");
}

unsigned char message[] = "Message to sign";
unsigned char signature[256];
size_t signature_len = sizeof(signature);

if (signMessageRsa3072Pss(message, sizeof(message) - 1, keypair_context, signature, signature_len)) {
    printf("RSA signature successful.\n");
} else {
    printf("RSA signature failed.\n");
}

bool is_valid;
if (verifyMessageRsa3072Pss(message, sizeof(message) - 1, keypair_context, signature, signature_len, &is_valid) && is_valid) {
    printf("RSA signature verification successful.\n");
} else {
    printf("RSA signature verification failed.\n");
}

cleanKeyContext(&keypair_context);
