DhContext* dh_context;
unsigned char public_key[256];
unsigned char shared_secret[256];

if (startDh(&dh_context, public_key, sizeof(public_key))) {
    printf("Diffie-Hellman key exchange started.\n");
} else {
    printf("Diffie-Hellman key exchange failed.\n");
}

unsigned char peer_public_key[256] = { /* peer's public key */ };
if (getDhSharedSecret(dh_context, peer_public_key, sizeof(peer_public_key), shared_secret, sizeof(shared_secret))) {
    printf("Diffie-Hellman shared secret computed.\n");
} else {
    printf("Diffie-Hellman shared secret computation failed.\n");
}

cleanDhContext(&dh_context);
