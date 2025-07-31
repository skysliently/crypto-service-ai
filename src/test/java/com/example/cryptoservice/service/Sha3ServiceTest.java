package com.example.cryptoservice.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SHA-3系列算法服务测试类
 * 
 * 测试SHA-3系列算法的各项功能，包括不同算法的哈希计算、边界条件处理等。
 * 
 * @author Assistant
 * @since 1.0
 */
@SpringBootTest
class Sha3ServiceTest {

    @Autowired
    private Sha3Service sha3Service;

    private static final String TEST_INPUT = "Hello, SHA-3 Test!";
    private static final String EMPTY_INPUT = "";
    private static final String LONG_INPUT = "This is a very long input string for testing SHA-3 algorithms. " +
            "It contains multiple sentences and should provide enough data to test " +
            "the hashing algorithms thoroughly. The SHA-3 family includes SHA3-224, " +
            "SHA3-256, SHA3-384, and SHA3-512 algorithms.";

    @Test
    void testSha3_256WithString() {
        String result = sha3Service.sha3_256(TEST_INPUT);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("^[0-9a-fA-F]+$"));
    }

    @Test
    void testSha3_256WithBytes() {
        byte[] inputBytes = TEST_INPUT.getBytes();
        String result = sha3Service.sha3_256(inputBytes);
        assertNotNull(result);
        assertEquals(64, result.length());
        assertTrue(result.matches("^[0-9a-fA-F]+$"));
    }

    @Test
    void testSha3_256EmptyString() {
        String result = sha3Service.sha3_256(EMPTY_INPUT);
        assertNotNull(result);
        assertEquals(64, result.length());
    }

    @Test
    void testSha3_512WithString() {
        String result = sha3Service.sha3_512(TEST_INPUT);
        assertNotNull(result);
        assertEquals(128, result.length());
        assertTrue(result.matches("^[0-9a-fA-F]+$"));
    }

    @Test
    void testSha3_512WithBytes() {
        byte[] inputBytes = TEST_INPUT.getBytes();
        String result = sha3Service.sha3_512(inputBytes);
        assertNotNull(result);
        assertEquals(128, result.length());
        assertTrue(result.matches("^[0-9a-fA-F]+$"));
    }

    @Test
    void testSha3_384WithString() {
        String result = sha3Service.sha3_384(TEST_INPUT);
        assertNotNull(result);
        assertEquals(96, result.length());
        assertTrue(result.matches("^[0-9a-fA-F]+$"));
    }

    @Test
    void testSha3_384WithBytes() {
        byte[] inputBytes = TEST_INPUT.getBytes();
        String result = sha3Service.sha3_384(inputBytes);
        assertNotNull(result);
        assertEquals(96, result.length());
        assertTrue(result.matches("^[0-9a-fA-F]+$"));
    }

    @Test
    void testSha3_224WithString() {
        String result = sha3Service.sha3_224(TEST_INPUT);
        assertNotNull(result);
        assertEquals(56, result.length());
        assertTrue(result.matches("^[0-9a-fA-F]+$"));
    }

    @Test
    void testSha3_224WithBytes() {
        byte[] inputBytes = TEST_INPUT.getBytes();
        String result = sha3Service.sha3_224(inputBytes);
        assertNotNull(result);
        assertEquals(56, result.length());
        assertTrue(result.matches("^[0-9a-fA-F]+$"));
    }

    @Test
    void testHashWithAlgorithmParameter() {
        String result = sha3Service.computeHash(TEST_INPUT, "SHA3-256");
        assertNotNull(result);
        assertEquals(64, result.length());
        
        String directResult = sha3Service.sha3_256(TEST_INPUT);
        assertEquals(directResult, result);
    }

    @Test
    void testHashWithDifferentAlgorithms() {
        String sha3_256Result = sha3Service.computeHash(TEST_INPUT, "SHA3-256");
        String sha3_512Result = sha3Service.computeHash(TEST_INPUT, "SHA3-512");
        String sha3_384Result = sha3Service.computeHash(TEST_INPUT, "SHA3-384");
        String sha3_224Result = sha3Service.computeHash(TEST_INPUT, "SHA3-224");

        assertNotNull(sha3_256Result);
        assertNotNull(sha3_512Result);
        assertNotNull(sha3_384Result);
        assertNotNull(sha3_224Result);

        assertEquals(64, sha3_256Result.length());
        assertEquals(128, sha3_512Result.length());
        assertEquals(96, sha3_384Result.length());
        assertEquals(56, sha3_224Result.length());
    }

    @Test
    void testLongInput() {
        String sha3_256Result = sha3Service.sha3_256(LONG_INPUT);
        String sha3_512Result = sha3Service.sha3_512(LONG_INPUT);
        
        assertNotNull(sha3_256Result);
        assertNotNull(sha3_512Result);
        assertEquals(64, sha3_256Result.length());
        assertEquals(128, sha3_512Result.length());
    }

    @Test
    void testNullInput() {
        assertThrows(IllegalArgumentException.class, () -> sha3Service.sha3_256((String) null));
        assertThrows(IllegalArgumentException.class, () -> sha3Service.sha3_256((byte[]) null));
        assertThrows(IllegalArgumentException.class, () -> sha3Service.computeHash((String) null, "SHA3-256"));
    }

    @Test
    void testInvalidAlgorithm() {
        assertThrows(IllegalArgumentException.class, () -> sha3Service.computeHash(TEST_INPUT, "INVALID"));
        assertThrows(IllegalArgumentException.class, () -> sha3Service.computeHash(TEST_INPUT, ""));
        assertThrows(IllegalArgumentException.class, () -> sha3Service.computeHash(TEST_INPUT, null));
    }

    @Test
    void testCaseInsensitiveAlgorithm() {
        String result1 = sha3Service.computeHash(TEST_INPUT, "SHA3-256");
        String result2 = sha3Service.computeHash(TEST_INPUT, "sha3-256");
        String result3 = sha3Service.computeHash(TEST_INPUT, "Sha3-256");

        assertEquals(result1, result2);
        assertEquals(result1, result3);
    }

    @Test
    void testResultConsistency() {
        String result1 = sha3Service.sha3_256(TEST_INPUT);
        String result2 = sha3Service.sha3_256(TEST_INPUT);
        
        assertEquals(result1, result2);
    }
}