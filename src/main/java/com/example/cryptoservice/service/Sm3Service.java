package com.example.cryptoservice.service;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Service;

/**
 * SM3哈希算法服务类
 * 
 * SM3是中国国家密码管理局发布的密码杂凑算法，
 * 是一种专门设计用于数字签名和验证、消息认证码生成和验证以及随机数生成的密码杂凑算法。
 * SM3算法的压缩函数与SHA-256相似，但采用了不同的置换函数和常量。
 * SM3算法的消息分组长度为512位，摘要值长度为256位。
 */
@Service
public class Sm3Service {

    /**
     * 计算输入字符串的SM3哈希值
     * 
     * 使用BouncyCastle库的SM3Digest实现SM3哈希计算。
     * 该方法首先验证输入参数，然后将字符串转换为字节数组，
     * 使用SM3算法计算哈希值，并将结果转换为十六进制字符串返回。
     * 
     * @param input 输入字符串，不能为空
     * @return 十六进制编码的SM3哈希值
     * @throws IllegalArgumentException 当输入字符串为null或空时抛出
     */
    public String computeSm3Hash(String input) {
        // 验证输入参数
        if (input == null || input.isEmpty()) {
            throw new IllegalArgumentException("Input string cannot be null or empty");
        }

        // 创建SM3摘要实例
        SM3Digest digest = new SM3Digest();
        // 将输入字符串转换为字节数组
        byte[] inputBytes = input.getBytes();
        // 更新摘要内容
        digest.update(inputBytes, 0, inputBytes.length);
        // 创建用于存储摘要结果的字节数组
        byte[] result = new byte[digest.getDigestSize()];
        // 完成摘要计算
        digest.doFinal(result, 0);

        // 将字节数组转换为十六进制字符串并返回
        return Hex.toHexString(result);
    }

    /**
     * 计算输入字节数组的SM3哈希值
     * 
     * 使用BouncyCastle库的SM3Digest实现SM3哈希计算。
     * 该方法首先验证输入参数，然后直接使用字节数组进行SM3算法计算，
     * 并将结果转换为十六进制字符串返回。
     * 
     * @param inputBytes 输入字节数组，不能为空
     * @return 十六进制编码的SM3哈希值
     * @throws IllegalArgumentException 当输入字节数组为null或空时抛出
     */
    public String computeSm3Hash(byte[] inputBytes) {
        // 验证输入参数
        if (inputBytes == null || inputBytes.length == 0) {
            throw new IllegalArgumentException("Input byte array cannot be null or empty");
        }

        // 创建SM3摘要实例
        SM3Digest digest = new SM3Digest();
        // 更新摘要内容
        digest.update(inputBytes, 0, inputBytes.length);
        // 创建用于存储摘要结果的字节数组
        byte[] result = new byte[digest.getDigestSize()];
        // 完成摘要计算
        digest.doFinal(result, 0);

        // 将字节数组转换为十六进制字符串并返回
        return Hex.toHexString(result);
    }
}