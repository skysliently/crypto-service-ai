package com.example.cryptoservice.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.example.cryptoservice.service.Sm2Service;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/sm2")
public class Sm2Controller {

    private final Sm2Service sm2Service;

    public Sm2Controller(Sm2Service sm2Service) {
        this.sm2Service = sm2Service;
    }

    /**
     * 统一的错误响应结构
     * @param message 错误消息
     * @param status HTTP状态码
     * @return ResponseEntity
     */
    private ResponseEntity<Map<String, Object>> createErrorResponse(String message, HttpStatus status) {
        Map<String, Object> error = new HashMap<>();
        error.put("success", false);
        error.put("message", message);
        return ResponseEntity.status(status).body(error);
    }

    /**
     * 参数验证方法
     * @param value 参数值
     * @param paramName 参数名称
     * @return 验证结果，如果验证失败返回错误响应，否则返回null
     */
    private ResponseEntity<Map<String, Object>> validateParameter(String value, String paramName) {
        if (value == null || value.isEmpty()) {
            return createErrorResponse("Parameter '" + paramName + "' is required", HttpStatus.BAD_REQUEST);
        }
        return null;
    }

    /**
     * 生成SM2密钥对
     * @return 包含公钥和私钥的响应
     */
    @PostMapping("/keypair")
    public ResponseEntity<Map<String, Object>> generateKeyPair() {
        try {
            KeyPair keyPair = sm2Service.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("publicKey", sm2Service.getPublicKeyHex(publicKey));
            response.put("privateKey", sm2Service.getPrivateKeyHex(privateKey));

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            // 记录详细异常信息用于调试，但不暴露给客户端
            e.printStackTrace();
            return createErrorResponse("Failed to generate key pair", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * SM2签名
     * @param request 请求体，包含data、privateKey字段
     * @return 包含签名值的响应
     */
    @PostMapping("/sign")
    public ResponseEntity<Map<String, Object>> sign(@RequestBody Map<String, String> request) {
        try {
            String data = request.get("data");
            String privateKeyHex = request.get("privateKey");

            // 使用统一的参数验证方法
            ResponseEntity<Map<String, Object>> validationError = validateParameter(data, "data");
            if (validationError != null) return validationError;
            
            validationError = validateParameter(privateKeyHex, "privateKey");
            if (validationError != null) return validationError;

            PrivateKey privateKey = sm2Service.restorePrivateKey(privateKeyHex);
            // 明确指定UTF-8编码
            String signature = sm2Service.sign(data.getBytes(StandardCharsets.UTF_8), privateKey);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", data);
            response.put("signature", signature);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            // 记录详细异常信息用于调试，但不暴露给客户端
            e.printStackTrace();
            return createErrorResponse("Failed to sign data", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * SM2验签
     * @param request 请求体，包含data、signature、publicKey字段
     * @return 验签结果
     */
    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verify(@RequestBody Map<String, String> request) {
        try {
            String data = request.get("data");
            String signature = request.get("signature");
            String publicKeyHex = request.get("publicKey");

            // 使用统一的参数验证方法
            ResponseEntity<Map<String, Object>> validationError = validateParameter(data, "data");
            if (validationError != null) return validationError;
            
            validationError = validateParameter(signature, "signature");
            if (validationError != null) return validationError;
            
            validationError = validateParameter(publicKeyHex, "publicKey");
            if (validationError != null) return validationError;

            PublicKey publicKey = sm2Service.restorePublicKey(publicKeyHex);
            // 明确指定UTF-8编码
            boolean result = sm2Service.verify(data.getBytes(StandardCharsets.UTF_8), signature, publicKey);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", data);
            response.put("signature", signature);
            response.put("verified", result);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            // 记录详细异常信息用于调试，但不暴露给客户端
            e.printStackTrace();
            return createErrorResponse("Failed to verify signature", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * SM2加密
     * @param request 请求体，包含data、publicKey字段
     * @return 加密结果
     */
    @PostMapping("/encrypt")
    public ResponseEntity<Map<String, Object>> encrypt(@RequestBody Map<String, String> request) {
        try {
            String data = request.get("data");
            String publicKeyHex = request.get("publicKey");

            // 使用统一的参数验证方法
            ResponseEntity<Map<String, Object>> validationError = validateParameter(data, "data");
            if (validationError != null) return validationError;
            
            validationError = validateParameter(publicKeyHex, "publicKey");
            if (validationError != null) return validationError;

            PublicKey publicKey = sm2Service.restorePublicKey(publicKeyHex);
            // 明确指定UTF-8编码
            String encryptedData = sm2Service.encrypt(data.getBytes(StandardCharsets.UTF_8), publicKey);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", data);
            response.put("encryptedData", encryptedData);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            // 记录详细异常信息用于调试，但不暴露给客户端
            e.printStackTrace();
            return createErrorResponse("Failed to encrypt data", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * SM2解密
     * @param request 请求体，包含encryptedData、privateKey字段
     * @return 解密结果
     */
    @PostMapping("/decrypt")
    public ResponseEntity<Map<String, Object>> decrypt(@RequestBody Map<String, String> request) {
        try {
            String encryptedData = request.get("encryptedData");
            String privateKeyHex = request.get("privateKey");

            // 使用统一的参数验证方法
            ResponseEntity<Map<String, Object>> validationError = validateParameter(encryptedData, "encryptedData");
            if (validationError != null) return validationError;
            
            validationError = validateParameter(privateKeyHex, "privateKey");
            if (validationError != null) return validationError;

            PrivateKey privateKey = sm2Service.restorePrivateKey(privateKeyHex);
            byte[] decryptedData = sm2Service.decrypt(encryptedData, privateKey);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("encryptedData", encryptedData);
            // 明确指定UTF-8编码
            response.put("decryptedData", new String(decryptedData, StandardCharsets.UTF_8));
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            // 记录详细异常信息用于调试，但不暴露给客户端
            e.printStackTrace();
            return createErrorResponse("Failed to decrypt data", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}