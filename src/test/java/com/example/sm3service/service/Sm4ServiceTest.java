package com.example.sm3service.service;

import org.junit.jupiter.api.Test;

import com.example.cryptoservice.service.Sm4Service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.bouncycastle.util.encoders.Hex;
import java.nio.charset.StandardCharsets;

public class Sm4ServiceTest {
    private final Sm4Service sm4Service = new Sm4Service();
    private static final String key = "30313233343536373839616263646566"; // 16字节密钥的十六进制表示
    private final String plainText = "616263";
    private final String iv = "000102030405060708090a0b0c0d0e0f";

    @Test
    void testEncryptDecryptECB() {
        byte[] plainBytes = Hex.decode(plainText);
        byte[] keyBytes = Hex.decode(key);
        byte[] encrypted = sm4Service.encrypt(plainBytes, keyBytes);
        byte[] decrypted = sm4Service.decrypt(encrypted, keyBytes);
        assertEquals(plainText, Hex.toHexString(decrypted));
    }

    @Test
    void testEncryptDecryptCBC() {
        String encrypted = sm4Service.encrypt(plainText, key, "CBC", iv);
        String decrypted = sm4Service.decrypt(encrypted, key, "CBC", iv);
        assertEquals(plainText, decrypted);
    }

    @Test
    void testEncryptDecryptGCM() {
        String gcmIv = "000102030405060708090a0b";
        String encrypted = sm4Service.encrypt(plainText, key, "GCM", gcmIv);
        String decrypted = sm4Service.decrypt(encrypted, key, "GCM", gcmIv);
        assertEquals(plainText, decrypted);
    }
}