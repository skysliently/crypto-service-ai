package com.example.cryptoservice.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SHA-2系列算法服务测试类
 * 
 * 测试SHA-2系列算法的各项功能，包括不同算法的哈希计算、边界条件处理等。
 * 
 * @author Assistant
 * @since 1.0
 */
@SpringBootTest
class Sha2ServiceTest {

    @Autowired
    private Sha2Service sha2Service;

    private static final String TEST_INPUT = "Hello, SHA-2 Test!";
    private static final String EMPTY_INPUT = "";
    private static final String LONG_INPUT = "This is a very long input string for testing SHA-2 algorithms. " +
            "It contains multiple sentences and should provide enough data to test " +
            "the hashing algorithms thoroughly. The SHA-2 family includes SHA-224, " +
            "SHA-256, SHA-384, and SHA-512 algorithms.";

    @Test
    void testSha256WithString() {
        String result = sha2Service.sha256(TEST_INPUT);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("^[0-9a-fA-F]+$"));
    }

    @Test
    void testSha256WithBytes() {
        byte[] inputBytes = TEST_INPUT.getBytes();
        String result = sha2Service.sha256(inputBytes);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("^[0-9a-fA-F]+$"));
    }

    @Test
    void testSha256EmptyString() {
        String result = sha2Service.sha256(EMPTY_INPUT);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", result);
    }

    @Test
    void testSha512WithString() {
        String result = sha2Service.sha512(TEST_INPUT);
        assertNotNull(result);
        assertEquals(128, result.length());
        assertTrue(result.matches("^[0-9a-fA-F]+$"));
    }

    @Test
    void testSha512WithBytes() {
        byte[] inputBytes = TEST_INPUT.getBytes();
        String result = sha2Service.sha512(inputBytes);
        assertNotNull(result);
        assertEquals(128, result.length());
        assertTrue(result.matches("^[0-9a-fA-F]+$"));
    }

    @Test
    void testSha384WithString() {
        String result = sha2Service.sha384(TEST_INPUT);
        assertNotNull(result);
        assertEquals(96, result.length());
        assertTrue(result.matches("^[0-9a-fA-F]+$"));
    }

    @Test
    void testSha384WithBytes() {
        byte[] inputBytes = TEST_INPUT.getBytes();
        String result = sha2Service.sha384(inputBytes);
        assertNotNull(result);
        assertEquals(96, result.length());
        assertTrue(result.matches("^[0-9a-fA-F]+$"));
    }

    @Test
    void testSha224WithString() {
        String result = sha2Service.sha224(TEST_INPUT);
        assertNotNull(result);
        assertEquals(56, result.length());
        assertTrue(result.matches("^[0-9a-fA-F]+$"));
    }

    @Test
    void testSha224WithBytes() {
        byte[] inputBytes = TEST_INPUT.getBytes();
        String result = sha2Service.sha224(inputBytes);
        assertNotNull(result);
        assertEquals(56, result.length());
        assertTrue(result.matches("^[0-9a-fA-F]+$"));
    }

    @Test
    void testHashWithAlgorithmParameter() {
        String result = sha2Service.computeHash(TEST_INPUT, "SHA-256");
        assertNotNull(result);
        assertEquals(64, result.length());
        
        String directResult = sha2Service.sha256(TEST_INPUT);
        assertEquals(directResult, result);
    }

    @Test
    void testHashWithDifferentAlgorithms() {
        String sha256Result = sha2Service.computeHash(TEST_INPUT, "SHA-256");
        String sha512Result = sha2Service.computeHash(TEST_INPUT, "SHA-512");
        String sha384Result = sha2Service.computeHash(TEST_INPUT, "SHA-384");
        String sha224Result = sha2Service.computeHash(TEST_INPUT, "SHA-224");

        assertNotNull(sha256Result);
        assertNotNull(sha512Result);
        assertNotNull(sha384Result);
        assertNotNull(sha224Result);

        assertEquals(64, sha256Result.length());
        assertEquals(128, sha512Result.length());
        assertEquals(96, sha384Result.length());
        assertEquals(56, sha224Result.length());
    }

    @Test
    void testLongInput() {
        String sha256Result = sha2Service.sha256(LONG_INPUT);
        String sha512Result = sha2Service.sha512(LONG_INPUT);
        
        assertNotNull(sha256Result);
        assertNotNull(sha512Result);
        assertEquals(64, sha256Result.length());
        assertEquals(128, sha512Result.length());
    }

    @Test
    void testNullInput() {
        assertThrows(IllegalArgumentException.class, () -> sha2Service.sha256((String) null));
        assertThrows(IllegalArgumentException.class, () -> sha2Service.sha256((byte[]) null));
        assertThrows(IllegalArgumentException.class, () -> sha2Service.computeHash((String) null, "SHA-256"));
    }

    @Test
    void testInvalidAlgorithm() {
        assertThrows(IllegalArgumentException.class, () -> sha2Service.computeHash(TEST_INPUT, "INVALID"));
        assertThrows(IllegalArgumentException.class, () -> sha2Service.computeHash(TEST_INPUT, ""));
        assertThrows(IllegalArgumentException.class, () -> sha2Service.computeHash(TEST_INPUT, null));
    }

    @Test
    void testCaseInsensitiveAlgorithm() {
        String result1 = sha2Service.computeHash(TEST_INPUT, "SHA-256");
        String result2 = sha2Service.computeHash(TEST_INPUT, "sha-256");
        String result3 = sha2Service.computeHash(TEST_INPUT, "Sha-256");

        assertEquals(result1, result2);
        assertEquals(result1, result3);
    }
}