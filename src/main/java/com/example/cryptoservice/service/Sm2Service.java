package com.example.cryptoservice.service;

import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * SM2国密算法服务类
 * 
 * SM2是一种基于椭圆曲线的公钥密码算法，包含数字签名、密钥交换和公钥加密等功能。
 * 本类基于BouncyCastle库实现SM2算法的相关操作。
 * 
 * 主要功能包括：
 * 1. SM2密钥对生成
 * 2. SM2数字签名与验签
 * 3. SM2公钥加密与私钥解密
 * 4. 密钥的序列化与反序列化
 */
@Service
public class Sm2Service {
    // 在静态初始化块中添加BouncyCastle安全提供者
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // 算法常量定义
    private static final String ALGORITHM_NAME = "ECDSA";  // 椭圆曲线数字签名算法名称
    private static final String PROVIDER_NAME = "BC";     // BouncyCastle安全提供者名称
    private static final String SIGNATURE_ALGORITHM = "SM3WithSM2";  // SM2签名使用的SM3摘要算法

    /**
     * 生成SM2密钥对
     * 
     * 使用BouncyCastle提供者的ECDSA算法和sm2p256v1参数规格生成SM2密钥对。
     * sm2p256v1是SM2算法标准中定义的椭圆曲线参数。
     * 
     * @return KeyPair SM2密钥对，包含公钥和私钥
     * @throws NoSuchAlgorithmException 当指定的算法不可用时抛出
     * @throws NoSuchProviderException 当指定的安全提供者不可用时抛出
     * @throws InvalidAlgorithmParameterException 当算法参数无效时抛出
     */
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        // 获取密钥对生成器实例
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_NAME, PROVIDER_NAME);
        // 使用SM2标准椭圆曲线参数
        ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        // 初始化密钥对生成器
        keyPairGenerator.initialize(sm2Spec);
        // 生成并返回密钥对
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * SM2签名
     * 
     * 使用SM2私钥对数据进行签名，采用SM3摘要算法。
     * 签名过程包括：
     * 1. 初始化签名对象
     * 2. 更新待签名数据
     * 3. 执行签名操作
     * 4. 将签名结果转换为十六进制字符串
     * 
     * @param data 待签名数据的字节数组
     * @param privateKey SM2私钥
     * @return 签名值的十六进制字符串表示
     * @throws Exception 签名过程中可能出现的异常
     */
    public String sign(byte[] data, PrivateKey privateKey) throws Exception {
        // 获取签名实例，使用SM3WithSM2算法
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM, PROVIDER_NAME);
        // 初始化签名对象，设置私钥
        signature.initSign(privateKey);
        // 更新待签名数据
        signature.update(data);
        // 执行签名操作
        byte[] signBytes = signature.sign();
        // 将签名结果转换为十六进制字符串返回
        return Hex.toHexString(signBytes);
    }

    /**
     * SM2验签
     * 
     * 使用SM2公钥验证数据签名的有效性。
     * 验签过程包括：
     * 1. 初始化验签对象
     * 2. 更新待验证数据
     * 3. 执行验签操作
     * 
     * @param data 待验证数据的字节数组
     * @param signature 签名值的十六进制字符串
     * @param publicKey SM2公钥
     * @return 验签结果，true表示签名有效，false表示签名无效
     * @throws Exception 验签过程中可能出现的异常
     */
    public boolean verify(byte[] data, String signature, PublicKey publicKey) throws Exception {
        // 获取签名实例，使用SM3WithSM2算法
        Signature sign = Signature.getInstance(SIGNATURE_ALGORITHM, PROVIDER_NAME);
        // 初始化验签对象，设置公钥
        sign.initVerify(publicKey);
        // 更新待验证数据
        sign.update(data);
        // 执行验签操作，将十六进制签名转换为字节数组进行验证
        return sign.verify(Hex.decode(signature));
    }

    /**
     * 将公钥序列化为十六进制字符串
     * 
     * 将BouncyCastle格式的SM2公钥转换为十六进制字符串表示，
     * 便于存储和传输。使用X.509编码格式。
     * 
     * @param publicKey SM2公钥对象
     * @return 公钥的十六进制字符串表示
     */
    public String serializePublicKey(PublicKey publicKey) {
        // 使用标准X.509编码格式序列化公钥
        return Hex.toHexString(publicKey.getEncoded());
    }

    /**
     * 从十六进制字符串恢复公钥
     * @param publicKeyHex 公钥的十六进制字符串
     * @return PublicKey 公钥对象
     * @throws Exception
     */
    public PublicKey restorePublicKey(String publicKeyHex) throws Exception {
        byte[] publicKeyBytes = Hex.decode(publicKeyHex);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_NAME, PROVIDER_NAME);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(publicKeySpec);
    }

    /**
     * 将私钥序列化为十六进制字符串
     * 
     * 将BouncyCastle格式的SM2私钥转换为十六进制字符串表示，
     * 便于存储和传输。使用PKCS#8编码格式。
     * 
     * @param privateKey SM2私钥对象
     * @return 私钥的十六进制字符串表示
     */
    public String serializePrivateKey(PrivateKey privateKey) {
        // 使用标准PKCS#8编码格式序列化私钥
        return Hex.toHexString(privateKey.getEncoded());
    }

    /**
     * 从十六进制字符串恢复私钥
     * @param privateKeyHex 私钥的十六进制字符串
     * @return PrivateKey 私钥对象
     * @throws Exception
     */
    public PrivateKey restorePrivateKey(String privateKeyHex) throws Exception {
        byte[] privateKeyBytes = Hex.decode(privateKeyHex);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_NAME, PROVIDER_NAME);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    /**
     * 获取公钥的十六进制字符串表示
     * 
     * 将公钥对象转换为十六进制字符串格式，便于存储和传输。
     * 使用未压缩格式编码公钥点。
     * 
     * @param publicKey SM2公钥对象
     * @return 公钥的十六进制字符串表示
     */
    public String getPublicKeyHex(PublicKey publicKey) {
        return serializePublicKey(publicKey);
    }

    /**
     * 获取私钥的十六进制字符串表示
     * 
     * 将私钥对象转换为十六进制字符串格式，便于存储和传输。
     * 
     * @param privateKey SM2私钥对象
     * @return 私钥的十六进制字符串表示
     */
    public String getPrivateKeyHex(PrivateKey privateKey) {
        return serializePrivateKey(privateKey);
    }

    /**
     * SM2加密
     * 
     * 使用SM2公钥对数据进行加密。采用C1C3C2格式的SM2引擎，
     * 并使用安全随机数生成器。
     * 
     * 加密过程包括：
     * 1. 将Java公钥转换为BouncyCastle格式
     * 2. 构造椭圆曲线域参数
     * 3. 创建公钥参数对象
     * 4. 初始化SM2引擎
     * 5. 执行加密操作
     * 
     * @param data 待加密数据的字节数组
     * @param publicKey SM2公钥
     * @return 密文的十六进制字符串表示
     * @throws Exception 加密过程中可能出现的异常
     */
    public String encrypt(byte[] data, PublicKey publicKey) throws Exception {
        // 将Java公钥转换为BouncyCastle格式
        BCECPublicKey bcEcPublicKey = (BCECPublicKey) publicKey;
        // 获取公钥参数规格
        ECParameterSpec parameterSpec = bcEcPublicKey.getParameters();
        // 构造椭圆曲线域参数
        ECDomainParameters domainParameters = new ECDomainParameters(parameterSpec.getCurve(), parameterSpec.getG(), parameterSpec.getN());
        // 创建公钥参数对象
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(bcEcPublicKey.getQ(), domainParameters);
        // 创建SM2引擎，使用C1C3C2格式
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        // 初始化加密引擎，使用安全随机数生成器
        sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
        // 执行加密操作
        byte[] encryptedData = sm2Engine.processBlock(data, 0, data.length);
        // 将密文转换为十六进制字符串返回
        return Hex.toHexString(encryptedData);
    }

    /**
     * SM2解密
     * 
     * 使用SM2私钥对密文进行解密。采用C1C3C2格式的SM2引擎。
     * 
     * 解密过程包括：
     * 1. 将Java私钥转换为BouncyCastle格式
     * 2. 构造椭圆曲线域参数
     * 3. 创建私钥参数对象
     * 4. 初始化SM2引擎
     * 5. 执行解密操作
     * 
     * @param data 待解密数据的十六进制字符串
     * @param privateKey SM2私钥
     * @return 明文的字节数组
     * @throws Exception 解密过程中可能出现的异常
     */
    public byte[] decrypt(String data, PrivateKey privateKey) throws Exception {
        // 将Java私钥转换为BouncyCastle格式
        BCECPrivateKey bcEcPrivateKey = (BCECPrivateKey) privateKey;
        // 获取私钥参数规格
        ECParameterSpec parameterSpec = bcEcPrivateKey.getParameters();
        // 构造椭圆曲线域参数
        ECDomainParameters domainParameters = new ECDomainParameters(parameterSpec.getCurve(), parameterSpec.getG(), parameterSpec.getN());
        // 创建私钥参数对象
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(bcEcPrivateKey.getD(), domainParameters);
        // 创建SM2引擎，使用C1C3C2格式
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        // 初始化解密引擎
        sm2Engine.init(false, privateKeyParameters);
        // 将十六进制密文转换为字节数组
        byte[] dataBytes = Hex.decode(data);
        // 执行解密操作并返回明文
        return sm2Engine.processBlock(dataBytes, 0, dataBytes.length);
    }
}