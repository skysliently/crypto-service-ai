package com.example.cryptoservice.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * SHA-2系列哈希算法服务类
 * 
 * SHA-2（Secure Hash Algorithm 2）是美国国家安全局设计的一系列密码哈希函数，
 * 是SHA-1的后继版本，目前被广泛使用。SHA-2系列包括多个变体：
 * - SHA-224：224位输出，28字节
 * - SHA-256：256位输出，32字节（最常用）
 * - SHA-384：384位输出，48字节
 * - SHA-512：512位输出，64字节
 * - SHA-512/224：512位基础上截断为224位
 * - SHA-512/256：512位基础上截断为256位
 * 
 * 主要功能：
 * 1. 支持SHA-2系列所有主要算法
 * 2. 字符串和字节数组输入支持
 * 3. 十六进制编码输出
 * 4. 统一的API接口
 * 5. 高性能实现
 * 
 * 使用场景：
 * - 数据完整性验证
 * - 数字签名
 * - 密码存储
 * - 区块链技术
 * - 文件校验
 * 
 * @author Assistant
 * @since 1.0
 */
@Service
public class Sha2Service {

    static {
        // 注册BouncyCastle安全提供者
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** SHA-256算法名称 */
    private static final String SHA_256 = "SHA-256";
    /** SHA-512算法名称 */
    private static final String SHA_512 = "SHA-512";
    /** SHA-384算法名称 */
    private static final String SHA_384 = "SHA-384";
    /** SHA-224算法名称 */
    private static final String SHA_224 = "SHA-224";

    /**
     * 计算SHA-256哈希值
     * 
     * @param input 输入字符串
     * @return 十六进制编码的SHA-256哈希值
     */
    public String sha256(String input) {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        return sha256(input.getBytes());
    }

    /**
     * 计算SHA-256哈希值
     * 
     * @param inputBytes 输入字节数组
     * @return 十六进制编码的SHA-256哈希值
     */
    public String sha256(byte[] inputBytes) {
        if (inputBytes == null) {
            throw new IllegalArgumentException("Input bytes cannot be null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256, BouncyCastleProvider.PROVIDER_NAME);
            byte[] hash = digest.digest(inputBytes);
            return Hex.toHexString(hash);
        } catch (NoSuchAlgorithmException | java.security.NoSuchProviderException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * 计算SHA-512哈希值
     * 
     * @param input 输入字符串
     * @return 十六进制编码的SHA-512哈希值
     */
    public String sha512(String input) {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        return sha512(input.getBytes());
    }

    /**
     * 计算SHA-512哈希值
     * 
     * @param inputBytes 输入字节数组
     * @return 十六进制编码的SHA-512哈希值
     */
    public String sha512(byte[] inputBytes) {
        if (inputBytes == null) {
            throw new IllegalArgumentException("Input bytes cannot be null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_512, BouncyCastleProvider.PROVIDER_NAME);
            byte[] hash = digest.digest(inputBytes);
            return Hex.toHexString(hash);
        } catch (NoSuchAlgorithmException | java.security.NoSuchProviderException e) {
            throw new RuntimeException("SHA-512 algorithm not available", e);
        }
    }

    /**
     * 计算SHA-384哈希值
     * 
     * @param input 输入字符串
     * @return 十六进制编码的SHA-384哈希值
     */
    public String sha384(String input) {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        return sha384(input.getBytes());
    }

    /**
     * 计算SHA-384哈希值
     * 
     * @param inputBytes 输入字节数组
     * @return 十六进制编码的SHA-384哈希值
     */
    public String sha384(byte[] inputBytes) {
        if (inputBytes == null) {
            throw new IllegalArgumentException("Input bytes cannot be null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_384, BouncyCastleProvider.PROVIDER_NAME);
            byte[] hash = digest.digest(inputBytes);
            return Hex.toHexString(hash);
        } catch (NoSuchAlgorithmException | java.security.NoSuchProviderException e) {
            throw new RuntimeException("SHA-384 algorithm not available", e);
        }
    }

    /**
     * 计算SHA-224哈希值
     * 
     * @param input 输入字符串
     * @return 十六进制编码的SHA-224哈希值
     */
    public String sha224(String input) {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        return sha224(input.getBytes());
    }

    /**
     * 计算SHA-224哈希值
     * 
     * @param inputBytes 输入字节数组
     * @return 十六进制编码的SHA-224哈希值
     */
    public String sha224(byte[] inputBytes) {
        if (inputBytes == null) {
            throw new IllegalArgumentException("Input bytes cannot be null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_224, BouncyCastleProvider.PROVIDER_NAME);
            byte[] hash = digest.digest(inputBytes);
            return Hex.toHexString(hash);
        } catch (NoSuchAlgorithmException | java.security.NoSuchProviderException e) {
            throw new RuntimeException("SHA-224 algorithm not available", e);
        }
    }

    /**
     * 使用指定的SHA-2算法计算哈希值
     *
     * @param input 输入字符串
     * @param algorithm 算法名称 (SHA-224, SHA-256, SHA-384, SHA-512)
     * @return 哈希值的十六进制字符串
     */
    public String computeHash(String input, String algorithm) {
        if (input == null) {
            throw new IllegalArgumentException("输入不能为空");
        }
        return computeHash(input.getBytes(), algorithm);
    }

    /**
     * 使用指定的SHA-2算法计算哈希值
     *
     * @param input 输入字节数组
     * @param algorithm 算法名称 (SHA-224, SHA-256, SHA-384, SHA-512)
     * @return 哈希值的十六进制字符串
     */
    public String computeHash(byte[] input, String algorithm) {
        if (input == null) {
            throw new IllegalArgumentException("输入不能为空");
        }
        if (algorithm == null || algorithm.trim().isEmpty()) {
            throw new IllegalArgumentException("算法名称不能为空");
        }

        String normalizedAlgorithm = algorithm.trim().toUpperCase();
        switch (normalizedAlgorithm) {
            case "SHA-224":
                return sha224(input);
            case "SHA-256":
                return sha256(input);
            case "SHA-384":
                return sha384(input);
            case "SHA-512":
                return sha512(input);
            default:
                throw new IllegalArgumentException("不支持的SHA-2算法: " + algorithm);
        }
    }
}