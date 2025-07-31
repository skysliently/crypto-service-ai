package com.example.cryptoservice.service;

import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * RSA非对称加密算法服务类
 * 
 * RSA是一种广泛使用的非对称加密算法，基于大整数分解的数学难题。
 * 该服务类基于BouncyCastle实现，支持可配置的密钥长度，默认使用2048位。
 * 
 * 主要功能包括：
 * 1. RSA密钥对生成（支持1024、2048、4096位密钥长度）
 * 2. RSA公钥加密
 * 3. RSA私钥解密
 * 4. 密钥的序列化与反序列化（十六进制格式）
 * 5. 支持PKCS#1和PKCS#8密钥格式
 * 
 * 使用场景：
 * - 数据加密传输
 * - 数字签名验证
 * - 密钥交换协议
 * - 身份认证
 * 
 * @author Assistant
 * @since 1.0
 */
@Service
public class RsaService {
    
    /** 默认RSA密钥长度（2048位） */
    private static final int DEFAULT_KEY_SIZE = 2048;
    
    /** RSA算法名称 */
    private static final String RSA_ALGORITHM = "RSA";
    
    /** RSA/ECB/PKCS1Padding加密模式 */
    private static final String RSA_PADDING = "RSA/ECB/PKCS1Padding";
    
    /** BouncyCastle安全提供者名称 */
    private static final String PROVIDER_NAME = "BC";
    
    static {
        // 注册BouncyCastle安全提供者
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    
    /**
     * 生成RSA密钥对
     * 
     * 使用默认的2048位密钥长度生成RSA密钥对。
     * 
     * @return RSA密钥对（包含公钥和私钥）
     * @throws Exception 密钥生成过程中的异常
     */
    public KeyPair generateKeyPair() throws Exception {
        return generateKeyPair(DEFAULT_KEY_SIZE);
    }
    
    /**
     * 生成指定长度的RSA密钥对
     * 
     * 根据指定的密钥长度生成RSA密钥对。
     * 
     * @param keySize 密钥长度（支持1024、2048、4096位）
     * @return RSA密钥对（包含公钥和私钥）
     * @throws Exception 密钥生成过程中的异常
     */
    public KeyPair generateKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM, PROVIDER_NAME);
        keyPairGenerator.initialize(keySize, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }
    
    /**
     * RSA公钥加密
     * 
     * 使用RSA公钥对数据进行加密。采用RSA/ECB/PKCS1Padding模式。
     * 
     * @param data 待加密数据的字节数组
     * @param publicKey RSA公钥
     * @return 密文的十六进制字符串表示
     * @throws Exception 加密过程中的异常
     */
    public String encrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_PADDING, PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedData = cipher.doFinal(data);
        return Hex.toHexString(encryptedData);
    }
    
    /**
     * RSA私钥解密
     * 
     * 使用RSA私钥对密文进行解密。采用RSA/ECB/PKCS1Padding模式。
     * 
     * @param encryptedData 密文的十六进制字符串表示
     * @param privateKey RSA私钥
     * @return 解密后的原始数据字节数组
     * @throws Exception 解密过程中的异常
     */
    public byte[] decrypt(String encryptedData, PrivateKey privateKey) throws Exception {
        byte[] encryptedBytes = Hex.decode(encryptedData);
        Cipher cipher = Cipher.getInstance(RSA_PADDING, PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedBytes);
    }
    
    /**
     * RSA私钥加密（用于数字签名）
     * 
     * 使用RSA私钥对数据进行加密，通常用于数字签名。
     * 
     * @param data 待加密数据的字节数组
     * @param privateKey RSA私钥
     * @return 加密结果的十六进制字符串表示
     * @throws Exception 加密过程中的异常
     */
    public String encryptWithPrivateKey(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_PADDING, PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] encryptedData = cipher.doFinal(data);
        return Hex.toHexString(encryptedData);
    }
    
    /**
     * RSA公钥解密（用于数字签名验证）
     * 
     * 使用RSA公钥对密文进行解密，通常用于数字签名验证。
     * 
     * @param encryptedData 密文的十六进制字符串表示
     * @param publicKey RSA公钥
     * @return 解密后的原始数据字节数组
     * @throws Exception 解密过程中的异常
     */
    public byte[] decryptWithPublicKey(String encryptedData, PublicKey publicKey) throws Exception {
        byte[] encryptedBytes = Hex.decode(encryptedData);
        Cipher cipher = Cipher.getInstance(RSA_PADDING, PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(encryptedBytes);
    }
    
    /**
     * 将公钥序列化为十六进制字符串
     * 
     * 将RSA公钥转换为X.509编码格式的十六进制字符串。
     * 
     * @param publicKey RSA公钥对象
     * @return 公钥的十六进制字符串表示
     */
    public String serializePublicKey(PublicKey publicKey) {
        return Hex.toHexString(publicKey.getEncoded());
    }
    
    /**
     * 将私钥序列化为十六进制字符串
     * 
     * 将RSA私钥转换为PKCS#8编码格式的十六进制字符串。
     * 
     * @param privateKey RSA私钥对象
     * @return 私钥的十六进制字符串表示
     */
    public String serializePrivateKey(PrivateKey privateKey) {
        return Hex.toHexString(privateKey.getEncoded());
    }
    
    /**
     * 从十六进制字符串恢复公钥
     * 
     * 将十六进制字符串格式的公钥恢复为PublicKey对象。
     * 
     * @param publicKeyHex 公钥的十六进制字符串表示
     * @return RSA公钥对象
     * @throws Exception 密钥恢复过程中的异常
     */
    public PublicKey restorePublicKey(String publicKeyHex) throws Exception {
        byte[] keyBytes = Hex.decode(publicKeyHex);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM, PROVIDER_NAME);
        return keyFactory.generatePublic(keySpec);
    }
    
    /**
     * 从十六进制字符串恢复私钥
     * 
     * 将十六进制字符串格式的私钥恢复为PrivateKey对象。
     * 
     * @param privateKeyHex 私钥的十六进制字符串表示
     * @return RSA私钥对象
     * @throws Exception 密钥恢复过程中的异常
     */
    public PrivateKey restorePrivateKey(String privateKeyHex) throws Exception {
        byte[] keyBytes = Hex.decode(privateKeyHex);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM, PROVIDER_NAME);
        return keyFactory.generatePrivate(keySpec);
    }
    
    /**
     * 获取公钥模数（用于调试和验证）
     * 
     * @param publicKey RSA公钥对象
     * @return 公钥模数的十六进制字符串表示
     * @throws Exception 获取模数过程中的异常
     */
    public String getPublicKeyModulus(PublicKey publicKey) throws Exception {
        java.security.interfaces.RSAPublicKey rsaPublicKey = (java.security.interfaces.RSAPublicKey) publicKey;
        return rsaPublicKey.getModulus().toString(16);
    }
    
    /**
     * 获取公钥指数（用于调试和验证）
     * 
     * @param publicKey RSA公钥对象
     * @return 公钥指数的十六进制字符串表示
     * @throws Exception 获取指数过程中的异常
     */
    public String getPublicKeyExponent(PublicKey publicKey) throws Exception {
        java.security.interfaces.RSAPublicKey rsaPublicKey = (java.security.interfaces.RSAPublicKey) publicKey;
        return rsaPublicKey.getPublicExponent().toString(16);
    }
    
    /**
     * 获取私钥模数（用于调试和验证）
     * 
     * @param privateKey RSA私钥对象
     * @return 私钥模数的十六进制字符串表示
     * @throws Exception 获取模数过程中的异常
     */
    public String getPrivateKeyModulus(PrivateKey privateKey) throws Exception {
        java.security.interfaces.RSAPrivateKey rsaPrivateKey = (java.security.interfaces.RSAPrivateKey) privateKey;
        return rsaPrivateKey.getModulus().toString(16);
    }
    
    /**
     * 获取私钥指数（用于调试和验证）
     * 
     * @param privateKey RSA私钥对象
     * @return 私钥指数的十六进制字符串表示
     * @throws Exception 获取指数过程中的异常
     */
    public String getPrivateKeyExponent(PrivateKey privateKey) throws Exception {
        java.security.interfaces.RSAPrivateKey rsaPrivateKey = (java.security.interfaces.RSAPrivateKey) privateKey;
        return rsaPrivateKey.getPrivateExponent().toString(16);
    }
}