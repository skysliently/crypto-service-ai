package com.example.cryptoservice.service;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class Sm2ServiceTest {

    private final Sm2Service sm2Service = new Sm2Service();
    private final String testData = "This is test data for SM2 signature";
    private final String testEncryptionData = "This is test data for SM2 encryption";

    @Test
    void testGenerateKeyPair() throws Exception {
        KeyPair keyPair = sm2Service.generateKeyPair();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());

        // Test key serialization
        String publicKeyHex = sm2Service.serializePublicKey(keyPair.getPublic());
        String privateKeyHex = sm2Service.serializePrivateKey(keyPair.getPrivate());

        assertNotNull(publicKeyHex);
        assertNotNull(privateKeyHex);
        assertFalse(publicKeyHex.isEmpty());
        assertFalse(privateKeyHex.isEmpty());

        // Test key restoration
        PublicKey restoredPublicKey = sm2Service.restorePublicKey(publicKeyHex);
        PrivateKey restoredPrivateKey = sm2Service.restorePrivateKey(privateKeyHex);

        assertNotNull(restoredPublicKey);
        assertNotNull(restoredPrivateKey);
    }

    @Test
    void testSignAndVerify() throws Exception {
        // Generate key pair
        KeyPair keyPair = sm2Service.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Sign data
        String signature = sm2Service.sign(testData.getBytes(), privateKey);
        assertNotNull(signature);
        assertFalse(signature.isEmpty());

        // Verify signature
        boolean verified = sm2Service.verify(testData.getBytes(), signature, publicKey);
        assertTrue(verified);

        // Verify with wrong data should fail
        boolean verifiedWrong = sm2Service.verify("Wrong data".getBytes(), signature, publicKey);
        assertFalse(verifiedWrong);
    }

    @Test
    void testKeySerializationAndRestoration() throws Exception {
        // Generate key pair
        KeyPair keyPair = sm2Service.generateKeyPair();
        PublicKey originalPublicKey = keyPair.getPublic();
        PrivateKey originalPrivateKey = keyPair.getPrivate();

        // Serialize keys
        String publicKeyHex = sm2Service.serializePublicKey(originalPublicKey);
        String privateKeyHex = sm2Service.serializePrivateKey(originalPrivateKey);

        // Restore keys
        PublicKey restoredPublicKey = sm2Service.restorePublicKey(publicKeyHex);
        PrivateKey restoredPrivateKey = sm2Service.restorePrivateKey(privateKeyHex);

        // Sign with original private key and verify with restored public key
        String signature = sm2Service.sign(testData.getBytes(), originalPrivateKey);
        boolean verified = sm2Service.verify(testData.getBytes(), signature, restoredPublicKey);
        assertTrue(verified);

        // Sign with restored private key and verify with original public key
        String signature2 = sm2Service.sign(testData.getBytes(), restoredPrivateKey);
        boolean verified2 = sm2Service.verify(testData.getBytes(), signature2, originalPublicKey);
        assertTrue(verified2);
    }
    
    @Test
    void testEncryptionAndDecryption() throws Exception {
        // Generate key pair
        KeyPair keyPair = sm2Service.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        
        // Encrypt data
        String encryptedData = sm2Service.encrypt(testEncryptionData.getBytes(), publicKey);
        
        // Verify encrypted data is not null or empty
        assertNotNull(encryptedData);
        assertFalse(encryptedData.isEmpty());
        
        // Decrypt data
        byte[] decryptedData = sm2Service.decrypt(encryptedData, privateKey);
        
        // Verify decrypted data matches original
        assertEquals(testEncryptionData, new String(decryptedData));
        
        // Test with hex serialized keys
        String privateKeyHex = sm2Service.serializePrivateKey(privateKey);
        String publicKeyHex = sm2Service.serializePublicKey(publicKey);
        
        PrivateKey restoredPrivateKey = sm2Service.restorePrivateKey(privateKeyHex);
        PublicKey restoredPublicKey = sm2Service.restorePublicKey(publicKeyHex);
        
        // Encrypt with restored public key
        String encryptedData2 = sm2Service.encrypt(testEncryptionData.getBytes(), restoredPublicKey);
        
        // Decrypt with restored private key
        byte[] decryptedData2 = sm2Service.decrypt(encryptedData2, restoredPrivateKey);
        
        // Verify decrypted data matches original
        assertEquals(testEncryptionData, new String(decryptedData2));
    }
}