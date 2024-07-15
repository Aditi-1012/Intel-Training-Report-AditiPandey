unsigned char key[32] = {0};
unsigned char data[] = "Test message";
unsigned char hmac[32];

if (hmac_SHA256(key, sizeof(key), data, sizeof(data) - 1, hmac, sizeof(hmac))) {
    printf("HMAC-SHA256 successful.\n");
} else {
    printf("HMAC-SHA256 failed.\n");
}
