package com.example.cryptoservice.service;

import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * SM4对称加密算法服务类
 * 
 * SM4是中国国家密码管理局发布的分组密码算法，分组长度和密钥长度均为128位（16字节）。
 * 该服务类基于BouncyCastle实现，支持多种工作模式：
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
public class Sm4Service {
    /** SM4密钥长度（128位 = 16字节） */
    private static final int SM4_KEY_SIZE = 16;


    /**
     * SM4加密（字符串接口）
     * 
     * 使用指定的SM4工作模式对十六进制格式的明文进行加密。
     * 
     * @param plainText 十六进制格式的明文数据
     * @param key 十六进制格式的密钥（必须为16字节）
     * @param mode 工作模式（支持ECB、CBC、GCM）
     * @param iv 十六进制格式的初始化向量（ECB模式不需要，CBC模式需要16字节，GCM模式需要12字节）
     * @return 十六进制格式的密文
     * @throws IllegalArgumentException 当参数格式不正确或长度不符合要求时抛出
     * @throws SecurityException 当加密过程中发生错误时抛出
     */
    public String encrypt(String plainText, String key, String mode, String iv) {
        validateParameters(plainText, key, mode, iv);
        return process(true, Hex.decode(plainText), Hex.decode(key), mode, Hex.decode(iv));
    }

    /**
     * SM4解密（字符串接口）
     * 
     * 使用指定的SM4工作模式对十六进制格式的密文进行解密。
     * 
     * @param cipherText 十六进制格式的密文数据
     * @param key 十六进制格式的密钥（必须为16字节）
     * @param mode 工作模式（支持ECB、CBC、GCM）
     * @param iv 十六进制格式的初始化向量（ECB模式不需要，CBC模式需要16字节，GCM模式需要12字节）
     * @return 十六进制格式的明文
     * @throws IllegalArgumentException 当参数格式不正确或长度不符合要求时抛出
     * @throws SecurityException 当解密过程中发生错误时抛出
     */
    public String decrypt(String cipherText, String key, String mode, String iv) {
        validateParameters(cipherText, key, mode, iv);
        return process(false, Hex.decode(cipherText), Hex.decode(key), mode, Hex.decode(iv));
    }

    /**
     * SM4加密（字节数组接口）
     * 
     * 使用指定的SM4工作模式对字节数组形式的明文进行加密。
     * 
     * @param data 待加密的字节数据
     * @param key 加密密钥（必须为16字节）
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
     * SM4解密（字节数组接口）
     * 
     * 使用指定的SM4工作模式对字节数组形式的密文进行解密。
     * 
     * @param data 待解密的字节数据
     * @param key 解密密钥（必须为16字节）
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
     * SM4加密（ECB模式默认接口）
     * 
     * 使用ECB模式对字节数组形式的明文进行加密，不需要初始化向量。
     * 
     * @param data 待加密的字节数据
     * @param key 加密密钥（必须为16字节）
     * @return 加密后的字节数据
     * @throws IllegalArgumentException 当参数格式不正确或长度不符合要求时抛出
     * @throws SecurityException 当加密过程中发生错误时抛出
     */
    public byte[] encrypt(byte[] data, byte[] key) {
        return encrypt(data, key, "ECB", null);
    }

    /**
     * SM4解密（ECB模式默认接口）
     * 
     * 使用ECB模式对字节数组形式的密文进行解密，不需要初始化向量。
     * 
     * @param data 待解密的字节数据
     * @param key 解密密钥（必须为16字节）
     * @return 解密后的字节数据
     * @throws IllegalArgumentException 当参数格式不正确或长度不符合要求时抛出
     * @throws SecurityException 当解密过程中发生错误时抛出
     */
    public byte[] decrypt(byte[] data, byte[] key) {
        return decrypt(data, key, "ECB", null);
    }

    /**
     * SM4核心加密解密处理方法
     * 
     * 根据指定的工作模式和操作类型（加密/解密）执行SM4算法。
     * 
     * @param forEncryption true表示加密操作，false表示解密操作
     * @param data 待处理的数据
     * @param key 密钥（16字节）
     * @param mode 工作模式（ECB、CBC、GCM）
     * @param iv 初始化向量（ECB模式为null）
     * @return 处理结果的十六进制字符串
     * @throws SecurityException 当加密/解密过程中发生错误时抛出
     */
    private String process(boolean forEncryption, byte[] data, byte[] key, String mode, byte[] iv) {
        try {
            // 根据工作模式选择合适的转换格式
            // GCM模式使用NoPadding，其他模式使用PKCS7Padding
            String transformation = "GCM".equalsIgnoreCase(mode) ? 
                String.format("SM4/%s/NoPadding", mode) : 
                String.format("SM4/%s/PKCS7Padding", mode);
            
            // 获取BouncyCastle提供的SM4密码实例
            Cipher cipher = Cipher.getInstance(transformation, "BC");
            
            // 创建SM4密钥规范
            SecretKeySpec keySpec = new SecretKeySpec(key, "SM4");
            
            // 确定操作模式（加密或解密）
            int opMode = forEncryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;

            // 根据工作模式初始化密码对象
            if ("ECB".equalsIgnoreCase(mode)) {
                // ECB模式不需要初始化向量
                cipher.init(opMode, keySpec);
            } else {
                // CBC和GCM模式需要初始化向量
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(opMode, keySpec, ivSpec);
            }

            // 执行加密或解密操作
            byte[] result = cipher.doFinal(data);
            
            // 将结果转换为十六进制字符串返回
            return Hex.toHexString(result);
        } catch (Exception e) {
            throw new SecurityException("SM4 processing failed: " + e.getMessage(), e);
        }
    }

    /**
     * SM4参数验证方法
     * 
     * 验证所有输入参数的格式和长度是否符合SM4算法要求。
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
        
        // 根据工作模式确定所需的初始化向量长度
        int ivLength = "GCM".equalsIgnoreCase(mode) ? 12 : 16;
        
        // 验证CBC和GCM模式下的初始化向量
        if (("CBC".equalsIgnoreCase(mode) || "GCM".equalsIgnoreCase(mode)) && 
            (iv == null || 
             (iv instanceof byte[] && ((byte[]) iv).length != ivLength) || 
             (iv instanceof String && ((String) iv).length() != ivLength * 2))) {
            throw new IllegalArgumentException("IV must be " + ivLength + " bytes (" + ivLength * 2 + " hex characters) for " + mode + " mode");
        }
        
        // 验证数据参数
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
        
        if (data instanceof String) {
            String dataStr = (String) data;
            if (dataStr.isEmpty()) {
                throw new IllegalArgumentException("Data cannot be empty");
            }
            if (!dataStr.matches("^[0-9a-fA-F]+$")) {
                throw new IllegalArgumentException("Data must be a hex string");
            }
        } else if (data instanceof byte[]) {
            if (((byte[]) data).length == 0) {
                throw new IllegalArgumentException("Data cannot be empty");
            }
        } else {
            throw new IllegalArgumentException("Data must be a String or byte array");
        }

        // 验证密钥参数
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }
        
        if (key instanceof String) {
            String keyStr = (String) key;
            if (!keyStr.matches("^[0-9a-fA-F]+$")) {
                throw new IllegalArgumentException("Key must be a hex string");
            }
            byte[] keyBytes;
            try {
                keyBytes = Hex.decode(keyStr);
            } catch (DecoderException e) {
                throw new IllegalArgumentException("Key contains invalid hex characters");
            }
            if (keyBytes.length != SM4_KEY_SIZE) {
                throw new IllegalArgumentException("Invalid key length: " + keyBytes.length + ", must be 16 bytes");
            }
        } else if (key instanceof byte[]) {
            if (((byte[]) key).length != SM4_KEY_SIZE) {
                throw new IllegalArgumentException("Key must be 16 bytes");
            }
        } else {
            throw new IllegalArgumentException("Key must be a String or byte array");
        }
    }
    
    /**
     * 静态初始化块
     * 
     * 在类加载时注册BouncyCastle安全提供者，确保SM4算法的可用性。
     */
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}