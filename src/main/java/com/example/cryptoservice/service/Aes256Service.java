package com.example.cryptoservice.service;

import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

/**
 * AES256对称加密算法服务类
 * 
 * AES256（高级加密标准）是一种对称加密算法，使用256位（32字节）密钥长度。
 * 该服务类支持多种工作模式：
 * - ECB模式（电子密码本模式）：最简单的模式，不需要初始化向量(IV)
 * - CBC模式（密码分组链接模式）：需要16字节初始化向量，安全性高于ECB
 * - GCM模式（Galois/Counter Mode）：需要12字节初始化向量，提供认证加密功能
 * 
 * 所有输入输出均以十六进制字符串形式处理，便于传输和存储。
 * 
 * @author Assistant
 * @since 1.0
 */
@Service
public class Aes256Service {
    
    /** AES256密钥长度（256位 = 32字节） */
    private static final int AES256_KEY_SIZE = 32;
    
    /** AES块大小（128位 = 16字节） */
    private static final int AES_BLOCK_SIZE = 16;
    
    /** GCM模式IV长度（96位 = 12字节） */
    private static final int GCM_IV_SIZE = 12;

    /**
     * AES256加密（字符串接口）
     * 
     * 使用指定的AES256工作模式对十六进制格式的明文进行加密。
     * 
     * @param plainText 十六进制格式的明文数据
     * @param key 十六进制格式的密钥（必须为32字节）
     * @param mode 工作模式（支持ECB、CBC、GCM）
     * @param iv 十六进制格式的初始化向量（ECB模式不需要，CBC模式需要16字节，GCM模式需要12字节）
     * @return 十六进制格式的密文
     * @throws IllegalArgumentException 当参数格式不正确或长度不符合要求时抛出
     * @throws SecurityException 当加密过程中发生错误时抛出
     */
    public String encrypt(String plainText, String key, String mode, String iv) {
        validateParameters(plainText, key, mode, iv);
        try {
            byte[] ivBytes = "ECB".equalsIgnoreCase(mode) ? null : Hex.decode(iv);
            return process(true, Hex.decode(plainText), Hex.decode(key), mode, ivBytes);
        } catch (Exception e) {
            throw new SecurityException("Invalid hex string format", e);
        }
    }

    /**
     * AES256解密（字符串接口）
     * 
     * 使用指定的AES256工作模式对十六进制格式的密文进行解密。
     * 
     * @param cipherText 十六进制格式的密文数据
     * @param key 十六进制格式的密钥（必须为32字节）
     * @param mode 工作模式（支持ECB、CBC、GCM）
     * @param iv 十六进制格式的初始化向量（ECB模式不需要，CBC模式需要16字节，GCM模式需要12字节）
     * @return 十六进制格式的明文
     * @throws IllegalArgumentException 当参数格式不正确或长度不符合要求时抛出
     * @throws SecurityException 当解密过程中发生错误时抛出
     */
    public String decrypt(String cipherText, String key, String mode, String iv) {
        validateParameters(cipherText, key, mode, iv);
        try {
            byte[] ivBytes = "ECB".equalsIgnoreCase(mode) ? null : Hex.decode(iv);
            return process(false, Hex.decode(cipherText), Hex.decode(key), mode, ivBytes);
        } catch (Exception e) {
            throw new SecurityException("Invalid hex string format", e);
        }
    }

    /**
     * AES256加密（字节数组接口）
     * 
     * 使用指定的AES256工作模式对字节数组形式的明文进行加密。
     * 
     * @param data 待加密的字节数据
     * @param key 加密密钥（必须为32字节）
     * @param mode 工作模式（支持ECB、CBC、GCM）
     * @param iv 初始化向量（ECB模式不需要，CBC模式需要16字节，GCM模式需要12字节）
     * @return 加密后的字节数据
     * @throws IllegalArgumentException 当参数格式不正确或长度不符合要求时抛出
     * @throws SecurityException 当加密过程中发生错误时抛出
     */
    public byte[] encrypt(byte[] data, byte[] key, String mode, byte[] iv) {
        validateParameters(data, key, mode, iv);
        return Hex.decode(process(true, data, key, mode, iv));
    }

    /**
     * AES256解密（字节数组接口）
     * 
     * 使用指定的AES256工作模式对字节数组形式的密文进行解密。
     * 
     * @param data 待解密的字节数据
     * @param key 解密密钥（必须为32字节）
     * @param mode 工作模式（支持ECB、CBC、GCM）
     * @param iv 初始化向量（ECB模式不需要，CBC模式需要16字节，GCM模式需要12字节）
     * @return 解密后的字节数据
     * @throws IllegalArgumentException 当参数格式不正确或长度不符合要求时抛出
     * @throws SecurityException 当解密过程中发生错误时抛出
     */
    public byte[] decrypt(byte[] data, byte[] key, String mode, byte[] iv) {
        validateParameters(data, key, mode, iv);
        return Hex.decode(process(false, data, key, mode, iv));
    }

    /**
     * AES256加密（ECB模式默认接口）
     * 
     * 使用ECB模式对字节数组形式的明文进行加密，不需要初始化向量。
     * 
     * @param data 待加密的字节数据
     * @param key 加密密钥（必须为32字节）
     * @return 加密后的字节数据
     * @throws IllegalArgumentException 当参数格式不正确或长度不符合要求时抛出
     * @throws SecurityException 当加密过程中发生错误时抛出
     */
    public byte[] encrypt(byte[] data, byte[] key) {
        return encrypt(data, key, "ECB", null);
    }

    /**
     * AES256解密（ECB模式默认接口）
     * 
     * 使用ECB模式对字节数组形式的密文进行解密，不需要初始化向量。
     * 
     * @param data 待解密的字节数据
     * @param key 解密密钥（必须为32字节）
     * @return 解密后的字节数据
     * @throws IllegalArgumentException 当参数格式不正确或长度不符合要求时抛出
     * @throws SecurityException 当解密过程中发生错误时抛出
     */
    public byte[] decrypt(byte[] data, byte[] key) {
        return decrypt(data, key, "ECB", null);
    }

    /**
     * AES256核心加密解密处理方法
     * 
     * 根据指定的工作模式和操作类型（加密/解密）执行AES256算法。
     * 
     * @param forEncryption true表示加密操作，false表示解密操作
     * @param data 待处理的数据
     * @param key 密钥（32字节）
     * @param mode 工作模式（ECB、CBC、GCM）
     * @param iv 初始化向量（ECB模式为null）
     * @return 处理结果的十六进制字符串
     * @throws SecurityException 当加密/解密过程中发生错误时抛出
     */
    private String process(boolean forEncryption, byte[] data, byte[] key, String mode, byte[] iv) {
        try {
            // 根据工作模式选择合适的转换格式
            String transformation;
            if ("GCM".equalsIgnoreCase(mode)) {
                transformation = "AES/GCM/NoPadding";
            } else {
                transformation = "AES/" + mode.toUpperCase() + "/PKCS5Padding";
            }
            
            // 获取AES密码实例
            Cipher cipher = Cipher.getInstance(transformation);
            
            // 创建AES密钥规范
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            
            // 确定操作模式（加密或解密）
            int opMode = forEncryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;

            // 根据工作模式初始化密码对象
            if ("ECB".equalsIgnoreCase(mode)) {
                // ECB模式不需要初始化向量
                cipher.init(opMode, keySpec);
            } else if ("CBC".equalsIgnoreCase(mode)) {
                // CBC模式需要16字节IV
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(opMode, keySpec, ivSpec);
            } else if ("GCM".equalsIgnoreCase(mode)) {
                // GCM模式需要12字节IV
                javax.crypto.spec.GCMParameterSpec gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv);
                cipher.init(opMode, keySpec, gcmSpec);
            }

            // 执行加密或解密操作
            byte[] result = cipher.doFinal(data);
            
            // 将结果转换为十六进制字符串返回
            return Hex.toHexString(result);
        } catch (Exception e) {
            throw new SecurityException("AES256 processing failed: " + e.getMessage(), e);
        }
    }

    /**
     * AES256参数验证方法
     * 
     * 验证所有输入参数的格式和长度是否符合AES256算法要求。
     * 
     * @param data 待处理的数据（字符串或字节数组）
     * @param key 密钥（字符串或字节数组）
     * @param mode 工作模式（ECB、CBC、GCM）
     * @param iv 初始化向量（字符串或字节数组，ECB模式可为null）
     * @throws IllegalArgumentException 当任何参数不符合要求时抛出
     */
    private void validateParameters(Object data, Object key, String mode, Object iv) {
        // 验证工作模式是否支持
        if (mode == null || (!"ECB".equalsIgnoreCase(mode) && !"CBC".equalsIgnoreCase(mode) && !"GCM".equalsIgnoreCase(mode))) {
            throw new IllegalArgumentException("Unsupported mode: " + mode);
        }

        // 验证密钥长度
        byte[] keyBytes;
        if (key instanceof String) {
            keyBytes = Hex.decode((String) key);
        } else {
            keyBytes = (byte[]) key;
        }
        
        if (keyBytes.length != AES256_KEY_SIZE) {
            throw new IllegalArgumentException("Key must be 32 bytes (256 bits), got: " + keyBytes.length + " bytes");
        }

        // 验证数据不能为空
        byte[] dataBytes;
        if (data instanceof String) {
            dataBytes = Hex.decode((String) data);
        } else {
            dataBytes = (byte[]) data;
        }
        
        if (dataBytes == null || dataBytes.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }

        // 验证IV要求（ECB模式不需要IV）
        if (!"ECB".equalsIgnoreCase(mode)) {
            if (iv == null) {
                throw new IllegalArgumentException("IV is required for mode: " + mode);
            }
            
            byte[] ivBytes;
            if (iv instanceof String) {
                ivBytes = Hex.decode((String) iv);
            } else {
                ivBytes = (byte[]) iv;
            }
            
            if ("CBC".equalsIgnoreCase(mode) && ivBytes.length != 16) {
                throw new IllegalArgumentException("CBC mode requires 16-byte IV, got: " + ivBytes.length + " bytes");
            } else if ("GCM".equalsIgnoreCase(mode) && ivBytes.length != 12) {
                throw new IllegalArgumentException("GCM mode requires 12-byte IV, got: " + ivBytes.length + " bytes");
            }
        }

        // 验证IV参数
        if (!"ECB".equalsIgnoreCase(mode)) {
            byte[] ivBytes;
            if (iv instanceof String) {
                if (iv == null || ((String) iv).isEmpty()) {
                    throw new IllegalArgumentException("IV is required for " + mode + " mode");
                }
                ivBytes = Hex.decode((String) iv);
            } else {
                ivBytes = (byte[]) iv;
            }
            
            if (ivBytes == null) {
                throw new IllegalArgumentException("IV is required for " + mode + " mode");
            }
            
            if ("CBC".equalsIgnoreCase(mode) && ivBytes.length != AES_BLOCK_SIZE) {
                throw new IllegalArgumentException("CBC mode IV must be 16 bytes, got: " + ivBytes.length + " bytes");
            }
            
            if ("GCM".equalsIgnoreCase(mode) && ivBytes.length != GCM_IV_SIZE) {
                throw new IllegalArgumentException("GCM mode IV must be 12 bytes, got: " + ivBytes.length + " bytes");
            }
        }
    }

    /**
     * 生成AES256密钥
     * 
     * @return 32字节（256位）的随机密钥
     */
    public byte[] generateKey() {
        byte[] key = new byte[AES256_KEY_SIZE];
        new SecureRandom().nextBytes(key);
        return key;
    }

    /**
     * 生成初始化向量
     * 
     * @param mode 工作模式
     * @return 适合指定模式的IV
     */
    public byte[] generateIv(String mode) {
        if ("CBC".equalsIgnoreCase(mode)) {
            byte[] iv = new byte[AES_BLOCK_SIZE];
            new SecureRandom().nextBytes(iv);
            return iv;
        } else if ("GCM".equalsIgnoreCase(mode)) {
            byte[] iv = new byte[GCM_IV_SIZE];
            new SecureRandom().nextBytes(iv);
            return iv;
        }
        return null;
    }
}