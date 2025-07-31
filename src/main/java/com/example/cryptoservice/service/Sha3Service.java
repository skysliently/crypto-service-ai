package com.example.cryptoservice.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * SHA-3系列哈希算法服务类
 * 
 * SHA-3（Secure Hash Algorithm 3）是美国国家标准与技术研究院（NIST）发布的下一代哈希算法标准，
 * 基于Keccak算法设计，与SHA-2采用完全不同的设计思路。SHA-3系列包括：
 * - SHA3-224：224位输出，28字节
 * - SHA3-256：256位输出，32字节
 * - SHA3-384：384位输出，48字节
 * - SHA3-512：512位输出，64字节
 * 
 * SHA-3的主要优势：
 * 1. 抗量子计算攻击：设计思路与SHA-2不同，具有更好的抗量子计算能力
 * 2. 海绵结构：采用海绵结构（Sponge Construction），安全性更高
 * 3. 灵活性：支持任意输出长度
 * 4. 性能优秀：在硬件实现上性能优异
 * 
 * 主要功能：
 * 1. 支持SHA-3系列所有主要算法
 * 2. 字符串和字节数组输入支持
 * 3. 十六进制编码输出
 * 4. 统一的API接口
 * 5. 未来proof设计
 * 
 * 使用场景：
 * - 需要抗量子计算安全性的应用
 * - 区块链和加密货币
 * - 数字签名和证书
 * - 数据完整性验证
 * - 长期数据存储
 * 
 * @author Assistant
 * @since 1.0
 */
@Service
public class Sha3Service {

    static {
        // 注册BouncyCastle安全提供者
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** SHA3-256算法名称 */
    private static final String SHA3_256 = "SHA3-256";
    /** SHA3-512算法名称 */
    private static final String SHA3_512 = "SHA3-512";
    /** SHA3-384算法名称 */
    private static final String SHA3_384 = "SHA3-384";
    /** SHA3-224算法名称 */
    private static final String SHA3_224 = "SHA3-224";

    /**
     * 计算SHA3-256哈希值
     * 
     * @param input 输入字符串
     * @return 十六进制编码的SHA3-256哈希值
     */
    public String sha3_256(String input) {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        return sha3_256(input.getBytes());
    }

    /**
     * 计算SHA3-256哈希值
     * 
     * @param inputBytes 输入字节数组
     * @return 十六进制编码的SHA3-256哈希值
     */
    public String sha3_256(byte[] inputBytes) {
        if (inputBytes == null) {
            throw new IllegalArgumentException("Input bytes cannot be null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA3_256, BouncyCastleProvider.PROVIDER_NAME);
            byte[] hash = digest.digest(inputBytes);
            return Hex.toHexString(hash);
        } catch (NoSuchAlgorithmException | java.security.NoSuchProviderException e) {
            throw new RuntimeException("SHA3-256 algorithm not available", e);
        }
    }

    /**
     * 计算SHA3-512哈希值
     * 
     * @param input 输入字符串
     * @return 十六进制编码的SHA3-512哈希值
     */
    public String sha3_512(String input) {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        return sha3_512(input.getBytes());
    }

    /**
     * 计算SHA3-512哈希值
     * 
     * @param inputBytes 输入字节数组
     * @return 十六进制编码的SHA3-512哈希值
     */
    public String sha3_512(byte[] inputBytes) {
        if (inputBytes == null) {
            throw new IllegalArgumentException("Input bytes cannot be null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA3_512, BouncyCastleProvider.PROVIDER_NAME);
            byte[] hash = digest.digest(inputBytes);
            return Hex.toHexString(hash);
        } catch (NoSuchAlgorithmException | java.security.NoSuchProviderException e) {
            throw new RuntimeException("SHA3-512 algorithm not available", e);
        }
    }

    /**
     * 计算SHA3-384哈希值
     * 
     * @param input 输入字符串
     * @return 十六进制编码的SHA3-384哈希值
     */
    public String sha3_384(String input) {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        return sha3_384(input.getBytes());
    }

    /**
     * 计算SHA3-384哈希值
     * 
     * @param inputBytes 输入字节数组
     * @return 十六进制编码的SHA3-384哈希值
     */
    public String sha3_384(byte[] inputBytes) {
        if (inputBytes == null) {
            throw new IllegalArgumentException("Input bytes cannot be null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA3_384, BouncyCastleProvider.PROVIDER_NAME);
            byte[] hash = digest.digest(inputBytes);
            return Hex.toHexString(hash);
        } catch (NoSuchAlgorithmException | java.security.NoSuchProviderException e) {
            throw new RuntimeException("SHA3-384 algorithm not available", e);
        }
    }

    /**
     * 计算SHA3-224哈希值
     * 
     * @param input 输入字符串
     * @return 十六进制编码的SHA3-224哈希值
     */
    public String sha3_224(String input) {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        return sha3_224(input.getBytes());
    }

    /**
     * 计算SHA3-224哈希值
     * 
     * @param inputBytes 输入字节数组
     * @return 十六进制编码的SHA3-224哈希值
     */
    public String sha3_224(byte[] inputBytes) {
        if (inputBytes == null) {
            throw new IllegalArgumentException("Input bytes cannot be null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA3_224, BouncyCastleProvider.PROVIDER_NAME);
            byte[] hash = digest.digest(inputBytes);
            return Hex.toHexString(hash);
        } catch (NoSuchAlgorithmException | java.security.NoSuchProviderException e) {
            throw new RuntimeException("SHA3-224 algorithm not available", e);
        }
    }

    /**
     * 计算指定SHA-3算法的哈希值
     *
     * @param input 输入字符串
     * @param algorithm 算法名称 (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
     * @return 哈希值的十六进制字符串
     */
    public String computeHash(String input, String algorithm) {
        if (input == null) {
            throw new IllegalArgumentException("输入不能为空");
        }
        return computeHash(input.getBytes(), algorithm);
    }

    /**
     * 计算指定SHA-3算法的哈希值
     *
     * @param input 输入字节数组
     * @param algorithm 算法名称 (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
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
            case "SHA3-224":
                return sha3_224(input);
            case "SHA3-256":
                return sha3_256(input);
            case "SHA3-384":
                return sha3_384(input);
            case "SHA3-512":
                return sha3_512(input);
            default:
                throw new IllegalArgumentException("不支持的SHA-3算法: " + algorithm);
        }
    }
}