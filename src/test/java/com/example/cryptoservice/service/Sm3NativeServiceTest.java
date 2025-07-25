package com.example.cryptoservice.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class Sm3NativeServiceTest {

    @Autowired
    private Sm3NativeService sm3NativeService;

    /**
     * 测试空字符串的SM3哈希值
     * 标准测试向量：输入空字符串，预期结果应为1AB21D8355CFA17F8E61194831E81A8F22BE453212F676F7D2D817A091D5D672
     */
    // @Test
    // public void testEmptyStringHash() {
    //     String input = "";
    //     String expectedHash = "1ab21d8355cfa17f8e61194831e81a8f22be453212f676f7d2d817a091d5d672";
    //     String actualHash = sm3NativeService.computeSm3Hash(input);
    //     assertEquals(expectedHash, actualHash.toLowerCase());
    // }

    /**
     * 测试标准输入"abc"的SM3哈希值
     * 预期结果：66C7F0F462EEEDD9D1F2D46BDC10C2E697F13F54E53BFA2B6121C333C9DC64BBA
     */
    @Test
    public void testAbcStringHash() {
        String input = "abc";
        String expectedHash = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
        String actualHash = sm3NativeService.computeSm3Hash(input);
        assertEquals(expectedHash, actualHash.toLowerCase());
    }

    /**
     * 测试长输入字符串的SM3哈希值
     */
    @Test
    public void testLongStringHash() {
        String input = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
        String expectedHash = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732";
        String actualHash = sm3NativeService.computeSm3Hash(input);
        assertEquals(expectedHash, actualHash.toLowerCase());
    }

    /**
     * 测试字节数组输入的SM3哈希值
     */
    @Test
    public void testByteArrayHash() {
        byte[] inputBytes = "测试字节数组输入".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String expectedHash = "ba28a32e3e1d4a01d2063b22b185d5abe26375122124da5968832dadeb749711";
        String actualHash = sm3NativeService.computeSm3Hash(inputBytes);
        assertNotNull(actualHash);
        assertEquals(64, actualHash.length());
        assertEquals(expectedHash, actualHash.toLowerCase());
    }

    /**
     * 测试空输入异常处理
     */
    @Test
    public void testNullInput() {
        assertThrows(IllegalArgumentException.class, () -> {
            sm3NativeService.computeSm3Hash((String) null);
        });

        assertThrows(IllegalArgumentException.class, () -> {
            sm3NativeService.computeSm3Hash((byte[]) null);
        });
    }
}