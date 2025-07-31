package com.example.cryptoservice.controller;

import com.example.cryptoservice.service.RsaService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * RSA非对称加密算法控制器
 * 
 * 提供RESTful API接口，支持RSA算法的加密和解密操作。
 * 支持可配置的密钥长度，默认使用2048位安全长度。
 * 所有输入输出均采用十六进制字符串格式，便于传输和存储。
 * 
 * @author Assistant
 * @since 1.0
 */
@RestController
@RequestMapping("/api/rsa")
public class RsaController {

    private final RsaService rsaService;

    public RsaController(RsaService rsaService) {
        this.rsaService = rsaService;
    }

    /**
     * 生成RSA密钥对
     * 
     * @param request 请求参数，可选包含keySize字段
     * @return 包含公钥和私钥的响应
     */
    @PostMapping("/generate-key-pair")
    public ResponseEntity<Map<String, Object>> generateKeyPair(@RequestBody Map<String, Object> request) {
        try {
            int keySize = DEFAULT_KEY_SIZE;
            
            // 检查是否提供了自定义密钥长度
            if (request.containsKey("keySize")) {
                Object keySizeObj = request.get("keySize");
                if (keySizeObj instanceof Integer) {
                    keySize = (Integer) keySizeObj;
                } else if (keySizeObj instanceof String) {
                    try {
                        keySize = Integer.parseInt((String) keySizeObj);
                    } catch (NumberFormatException e) {
                        return createErrorResponse("Invalid keySize format", HttpStatus.BAD_REQUEST);
                    }
                }
            }

            // 验证密钥长度的有效性
            if (keySize < 1024 || keySize > 8192) {
                return createErrorResponse("Key size must be between 1024 and 8192 bits", HttpStatus.BAD_REQUEST);
            }

            // 生成密钥对
            KeyPair keyPair = rsaService.generateKeyPair(keySize);
            String publicKeyHex = rsaService.serializePublicKey(keyPair.getPublic());
            String privateKeyHex = rsaService.serializePrivateKey(keyPair.getPrivate());

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("publicKey", publicKeyHex);
            response.put("privateKey", privateKeyHex);
            response.put("keySize", keySize);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace();
            return createErrorResponse("Failed to generate RSA key pair", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * RSA公钥加密
     * 
     * @param request 请求体，包含data和publicKey字段
     * @return 加密结果
     */
    @PostMapping("/encrypt")
    public ResponseEntity<Map<String, Object>> encrypt(@RequestBody Map<String, String> request) {
        try {
            String data = request.get("data");
            String publicKeyHex = request.get("publicKey");

            // 参数验证
            ResponseEntity<Map<String, Object>> validationError = validateParameter(data, "data");
            if (validationError != null) return validationError;
            
            validationError = validateParameter(publicKeyHex, "publicKey");
            if (validationError != null) return validationError;

            // 恢复公钥并加密
            PublicKey publicKey = rsaService.restorePublicKey(publicKeyHex);
            String encryptedData = rsaService.encrypt(data.getBytes(), publicKey);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", data);
            response.put("encryptedData", encryptedData);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace();
            return createErrorResponse("Failed to encrypt data", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * RSA私钥解密
     * 
     * @param request 请求体，包含encryptedData和privateKey字段
     * @return 解密结果
     */
    @PostMapping("/decrypt")
    public ResponseEntity<Map<String, Object>> decrypt(@RequestBody Map<String, String> request) {
        try {
            String encryptedData = request.get("encryptedData");
            String privateKeyHex = request.get("privateKey");

            // 参数验证
            ResponseEntity<Map<String, Object>> validationError = validateParameter(encryptedData, "encryptedData");
            if (validationError != null) return validationError;
            
            validationError = validateParameter(privateKeyHex, "privateKey");
            if (validationError != null) return validationError;

            // 恢复私钥并解密
            PrivateKey privateKey = rsaService.restorePrivateKey(privateKeyHex);
            byte[] decryptedData = rsaService.decrypt(encryptedData, privateKey);
            String decryptedString = new String(decryptedData);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("decryptedData", decryptedString);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace();
            return createErrorResponse("Failed to decrypt data", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * RSA私钥加密（用于数字签名）
     * 
     * @param request 请求体，包含data和privateKey字段
     * @return 加密结果
     */
    @PostMapping("/encrypt-with-private")
    public ResponseEntity<Map<String, Object>> encryptWithPrivateKey(@RequestBody Map<String, String> request) {
        try {
            String data = request.get("data");
            String privateKeyHex = request.get("privateKey");

            // 参数验证
            ResponseEntity<Map<String, Object>> validationError = validateParameter(data, "data");
            if (validationError != null) return validationError;
            
            validationError = validateParameter(privateKeyHex, "privateKey");
            if (validationError != null) return validationError;

            // 恢复私钥并加密
            PrivateKey privateKey = rsaService.restorePrivateKey(privateKeyHex);
            String encryptedData = rsaService.encryptWithPrivateKey(data.getBytes(), privateKey);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", data);
            response.put("encryptedData", encryptedData);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace();
            return createErrorResponse("Failed to encrypt with private key", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * RSA公钥解密（用于数字签名验证）
     * 
     * @param request 请求体，包含encryptedData和publicKey字段
     * @return 解密结果
     */
    @PostMapping("/decrypt-with-public")
    public ResponseEntity<Map<String, Object>> decryptWithPublicKey(@RequestBody Map<String, String> request) {
        try {
            String encryptedData = request.get("encryptedData");
            String publicKeyHex = request.get("publicKey");

            // 参数验证
            ResponseEntity<Map<String, Object>> validationError = validateParameter(encryptedData, "encryptedData");
            if (validationError != null) return validationError;
            
            validationError = validateParameter(publicKeyHex, "publicKey");
            if (validationError != null) return validationError;

            // 恢复公钥并解密
            PublicKey publicKey = rsaService.restorePublicKey(publicKeyHex);
            byte[] decryptedData = rsaService.decryptWithPublicKey(encryptedData, publicKey);
            String decryptedString = new String(decryptedData);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("decryptedData", decryptedString);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace();
            return createErrorResponse("Failed to decrypt with public key", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * 获取密钥信息
     * 
     * @param request 请求体，包含publicKey或privateKey字段
     * @return 密钥详细信息
     */
    @PostMapping("/key-info")
    public ResponseEntity<Map<String, Object>> getKeyInfo(@RequestBody Map<String, String> request) {
        try {
            String publicKeyHex = request.get("publicKey");
            String privateKeyHex = request.get("privateKey");

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);

            if (publicKeyHex != null && !publicKeyHex.isEmpty()) {
                PublicKey publicKey = rsaService.restorePublicKey(publicKeyHex);
                response.put("publicKeyModulus", rsaService.getPublicKeyModulus(publicKey));
                response.put("publicKeyExponent", rsaService.getPublicKeyExponent(publicKey));
            }

            if (privateKeyHex != null && !privateKeyHex.isEmpty()) {
                PrivateKey privateKey = rsaService.restorePrivateKey(privateKeyHex);
                response.put("privateKeyModulus", rsaService.getPrivateKeyModulus(privateKey));
                response.put("privateKeyExponent", rsaService.getPrivateKeyExponent(privateKey));
            }

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace();
            return createErrorResponse("Failed to get key information", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * 参数验证工具方法
     * 
     * @param value 参数值
     * @param paramName 参数名称
     * @return 如果验证失败返回错误响应，否则返回null
     */
    private ResponseEntity<Map<String, Object>> validateParameter(String value, String paramName) {
        if (value == null || value.trim().isEmpty()) {
            return createErrorResponse(paramName + " cannot be empty", HttpStatus.BAD_REQUEST);
        }
        return null;
    }

    /**
     * 创建错误响应
     * 
     * @param message 错误消息
     * @param status HTTP状态码
     * @return 错误响应
     */
    private ResponseEntity<Map<String, Object>> createErrorResponse(String message, HttpStatus status) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("error", message);
        return ResponseEntity.status(status).body(response);
    }

    /** 默认RSA密钥长度 */
    private static final int DEFAULT_KEY_SIZE = 2048;
}