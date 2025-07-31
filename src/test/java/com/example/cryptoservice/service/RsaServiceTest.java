package com.example.cryptoservice.service;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RSA服务测试类
 * 
 * 测试RSA算法的各项功能，包括密钥生成、加密解密、密钥序列化与反序列化等。
 * 
 * @author Assistant
 * @since 1.0
 */
@SpringBootTest
class RsaServiceTest {

    private final RsaService rsaService = new RsaService();
    private final String testData = "Hello, RSA encryption test!";

    @Test
    void testGenerateKeyPair() throws Exception {
        // 测试默认密钥长度（2048位）
        KeyPair keyPair = rsaService.generateKeyPair();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        
        // 验证密钥类型
        assertTrue(keyPair.getPublic() instanceof java.security.interfaces.RSAPublicKey);
        assertTrue(keyPair.getPrivate() instanceof java.security.interfaces.RSAPrivateKey);
        
        // 测试指定密钥长度
        KeyPair keyPair1024 = rsaService.generateKeyPair(1024);
        assertNotNull(keyPair1024);
        
        KeyPair keyPair4096 = rsaService.generateKeyPair(4096);
        assertNotNull(keyPair4096);
    }

    @Test
    void testEncryptAndDecrypt() throws Exception {
        // 生成密钥对
        KeyPair keyPair = rsaService.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        // 加密数据
        String encryptedData = rsaService.encrypt(testData.getBytes(), publicKey);
        assertNotNull(encryptedData);
        assertFalse(encryptedData.isEmpty());
        
        // 解密数据
        byte[] decryptedData = rsaService.decrypt(encryptedData, privateKey);
        String decryptedString = new String(decryptedData);
        
        // 验证解密结果
        assertEquals(testData, decryptedString);
    }

    @Test
    void testEncryptWithPrivateKeyAndDecryptWithPublicKey() throws Exception {
        // 生成密钥对
        KeyPair keyPair = rsaService.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        // 使用私钥加密（模拟签名）
        String encryptedData = rsaService.encryptWithPrivateKey(testData.getBytes(), privateKey);
        assertNotNull(encryptedData);
        assertFalse(encryptedData.isEmpty());
        
        // 使用公钥解密（模拟验签）
        byte[] decryptedData = rsaService.decryptWithPublicKey(encryptedData, publicKey);
        String decryptedString = new String(decryptedData);
        
        // 验证解密结果
        assertEquals(testData, decryptedString);
    }

    @Test
    void testKeySerializationAndRestoration() throws Exception {
        // 生成密钥对
        KeyPair keyPair = rsaService.generateKeyPair();
        PublicKey originalPublicKey = keyPair.getPublic();
        PrivateKey originalPrivateKey = keyPair.getPrivate();
        
        // 序列化密钥
        String publicKeyHex = rsaService.serializePublicKey(originalPublicKey);
        String privateKeyHex = rsaService.serializePrivateKey(originalPrivateKey);
        
        assertNotNull(publicKeyHex);
        assertNotNull(privateKeyHex);
        assertFalse(publicKeyHex.isEmpty());
        assertFalse(privateKeyHex.isEmpty());
        
        // 反序列化密钥
        PublicKey restoredPublicKey = rsaService.restorePublicKey(publicKeyHex);
        PrivateKey restoredPrivateKey = rsaService.restorePrivateKey(privateKeyHex);
        
        assertNotNull(restoredPublicKey);
        assertNotNull(restoredPrivateKey);
        
        // 使用恢复的密钥进行加密解密测试
        String encryptedData = rsaService.encrypt(testData.getBytes(), restoredPublicKey);
        byte[] decryptedData = rsaService.decrypt(encryptedData, restoredPrivateKey);
        String decryptedString = new String(decryptedData);
        
        assertEquals(testData, decryptedString);
    }

    @Test
    void testCrossKeyUsage() throws Exception {
        // 生成两组密钥对
        KeyPair keyPair1 = rsaService.generateKeyPair();
        KeyPair keyPair2 = rsaService.generateKeyPair();
        
        // 使用第一组的公钥加密，第二组的私钥应该无法解密
        String encryptedData = rsaService.encrypt(testData.getBytes(), keyPair1.getPublic());
        
        // 尝试用第二组的私钥解密应该失败
        assertThrows(Exception.class, () -> {
            rsaService.decrypt(encryptedData, keyPair2.getPrivate());
        });
    }

    @Test
    void testEmptyDataHandling() throws Exception {
        KeyPair keyPair = rsaService.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        // 测试空数据
        String encryptedData = rsaService.encrypt("".getBytes(), publicKey);
        assertNotNull(encryptedData);
        
        byte[] decryptedData = rsaService.decrypt(encryptedData, privateKey);
        assertEquals(0, decryptedData.length);
    }

    @Test
    void testKeyInformation() throws Exception {
        KeyPair keyPair = rsaService.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        // 验证密钥信息获取
        String publicModulus = rsaService.getPublicKeyModulus(publicKey);
        String publicExponent = rsaService.getPublicKeyExponent(publicKey);
        String privateModulus = rsaService.getPrivateKeyModulus(privateKey);
        String privateExponent = rsaService.getPrivateKeyExponent(privateKey);
        
        assertNotNull(publicModulus);
        assertNotNull(publicExponent);
        assertNotNull(privateModulus);
        assertNotNull(privateExponent);
        
        // 公钥和私钥的模数应该相同
        assertEquals(publicModulus, privateModulus);
    }
}