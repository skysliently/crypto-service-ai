package com.example.cryptoservice.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class Aes256ServiceTest {

    private Aes256Service aes256Service;
    private String testKey;

    @BeforeEach
    void setUp() {
        aes256Service = new Aes256Service();
        // 32字节密钥（256位）的十六进制表示
        testKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    }

    @Test
    void testEncryptDecryptECB() {
        String plainText = "48656c6c6f20576f726c6421"; // "Hello World!" in hex
        
        // ECB模式加密
        String encrypted = aes256Service.encrypt(plainText, testKey, "ECB", null);
        assertNotNull(encrypted);
        assertNotEquals(plainText, encrypted);
        
        // ECB模式解密
        String decrypted = aes256Service.decrypt(encrypted, testKey, "ECB", null);
        assertEquals(plainText, decrypted);
    }

    @Test
    void testEncryptDecryptCBC() {
        String plainText = "48656c6c6f20576f726c6421"; // "Hello World!" in hex
        String iv = "0123456789abcdef0123456789abcdef"; // 16字节IV
        
        // CBC模式加密
        String encrypted = aes256Service.encrypt(plainText, testKey, "CBC", iv);
        assertNotNull(encrypted);
        assertNotEquals(plainText, encrypted);
        
        // CBC模式解密
        String decrypted = aes256Service.decrypt(encrypted, testKey, "CBC", iv);
        assertEquals(plainText, decrypted);
    }

    @Test
    void testEncryptDecryptGCM() {
        String plainText = "48656c6c6f20576f726c6421"; // "Hello World!" in hex
        String iv = "0123456789abcdef01234567"; // 12字节IV for GCM
        
        // GCM模式加密
        String encrypted = aes256Service.encrypt(plainText, testKey, "GCM", iv);
        assertNotNull(encrypted);
        assertNotEquals(plainText, encrypted);
        
        // GCM模式解密
        String decrypted = aes256Service.decrypt(encrypted, testKey, "GCM", iv);
        assertEquals(plainText, decrypted);
    }

    @Test
    void testByteArrayInterface() {
        byte[] plainBytes = "Hello World!".getBytes();
        byte[] keyBytes = aes256Service.generateKey();
        
        // 使用字节数组接口加密
        byte[] encrypted = aes256Service.encrypt(plainBytes, keyBytes, "ECB", null);
        assertNotNull(encrypted);
        assertNotEquals(plainBytes.length, encrypted.length); // 加密后长度可能不同
        
        // 使用字节数组接口解密
        byte[] decrypted = aes256Service.decrypt(encrypted, keyBytes, "ECB", null);
        assertArrayEquals(plainBytes, decrypted);
    }

    @Test
    void testKeyGeneration() {
        byte[] key = aes256Service.generateKey();
        assertNotNull(key);
        assertEquals(32, key.length); // 32字节 = 256位
        
        String keyHex = bytesToHex(key);
        assertEquals(64, keyHex.length()); // 32字节 = 64个十六进制字符
    }

    @Test
    void testIvGeneration() {
        // CBC模式IV
        byte[] cbcIv = aes256Service.generateIv("CBC");
        assertNotNull(cbcIv);
        assertEquals(16, cbcIv.length);
        
        // GCM模式IV
        byte[] gcmIv = aes256Service.generateIv("GCM");
        assertNotNull(gcmIv);
        assertEquals(12, gcmIv.length);
        
        // ECB模式不需要IV
        byte[] ecbIv = aes256Service.generateIv("ECB");
        assertNull(ecbIv);
    }

    @Test
    void testInvalidKeyLength() {
        String plainText = "48656c6c6f20576f726c6421";
        String shortKey = "0123456789abcdef"; // 16字节密钥，应该为32字节
        
        assertThrows(IllegalArgumentException.class, () -> {
            aes256Service.encrypt(plainText, shortKey, "ECB", null);
        });
    }

    @Test
    void testInvalidIvLength() {
        String plainText = "48656c6c6f20576f726c6421";
        String shortIv = "01234567"; // 8字节IV，CBC需要16字节
        
        assertThrows(IllegalArgumentException.class, () -> {
            aes256Service.encrypt(plainText, testKey, "CBC", shortIv);
        });
    }

    @Test
    void testInvalidMode() {
        String plainText = "48656c6c6f20576f726c6421";
        
        assertThrows(IllegalArgumentException.class, () -> {
            aes256Service.encrypt(plainText, testKey, "INVALID", null);
        });
    }

    @Test
    void testMissingIvForNonEcb() {
        String plainText = "48656c6c6f20576f726c6421";
        
        assertThrows(IllegalArgumentException.class, () -> {
            aes256Service.encrypt(plainText, testKey, "CBC", null);
        });
    }

    // 辅助方法：字节数组转十六进制字符串
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}