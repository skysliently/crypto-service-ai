package com.example.cryptoservice.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.example.cryptoservice.service.Sm4Service;

import java.util.HashMap;
import java.util.Map;

/**
 * SM4对称加密算法控制器
 * 
 * 提供RESTful API接口，支持SM4算法的加密和解密操作。
 * 支持多种工作模式：ECB、CBC、GCM。
 * 所有输入输出均采用十六进制字符串格式，便于传输和存储。
 * 
 * @author Assistant
 * @since 1.0
 */
@RestController
@RequestMapping("/api/sm4")
public class Sm4Controller {

    private final Sm4Service sm4Service;

    public Sm4Controller(Sm4Service sm4Service) {
        this.sm4Service = sm4Service;
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
     * SM4加密
     * @param request 请求体，包含plainText、key、mode、iv字段
     * @return 加密结果
     */
    @PostMapping("/encrypt")
    public ResponseEntity<Map<String, Object>> encrypt(@RequestBody Map<String, String> request) {
        try {
            String plainText = request.get("plainText");
            String key = request.get("key");
            String mode = request.getOrDefault("mode", "ECB");
            String iv = request.get("iv");

            // 使用统一的参数验证方法
            ResponseEntity<Map<String, Object>> validationError = validateParameter(plainText, "plainText");
            if (validationError != null) return validationError;
            
            validationError = validateParameter(key, "key");
            if (validationError != null) return validationError;

            // 验证模式参数
            if (!isValidMode(mode)) {
                return createErrorResponse("Invalid mode. Supported modes: ECB, CBC, GCM", HttpStatus.BAD_REQUEST);
            }

            // 验证IV参数（非ECB模式需要IV）
            if (!"ECB".equalsIgnoreCase(mode)) {
                validationError = validateParameter(iv, "iv");
                if (validationError != null) return validationError;
            }

            String encryptedData = sm4Service.encrypt(plainText, key, mode, iv);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("plainText", plainText);
            response.put("encryptedData", encryptedData);
            response.put("mode", mode.toUpperCase());
            if (!"ECB".equalsIgnoreCase(mode)) {
                response.put("iv", iv);
            }
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return createErrorResponse(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            // 记录详细异常信息用于调试，但不暴露给客户端
            e.printStackTrace();
            return createErrorResponse("Failed to encrypt data", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * SM4解密
     * @param request 请求体，包含encryptedData、key、mode、iv字段
     * @return 解密结果
     */
    @PostMapping("/decrypt")
    public ResponseEntity<Map<String, Object>> decrypt(@RequestBody Map<String, String> request) {
        try {
            String encryptedData = request.get("encryptedData");
            String key = request.get("key");
            String mode = request.getOrDefault("mode", "ECB");
            String iv = request.get("iv");

            // 使用统一的参数验证方法
            ResponseEntity<Map<String, Object>> validationError = validateParameter(encryptedData, "encryptedData");
            if (validationError != null) return validationError;
            
            validationError = validateParameter(key, "key");
            if (validationError != null) return validationError;

            // 验证模式参数
            if (!isValidMode(mode)) {
                return createErrorResponse("Invalid mode. Supported modes: ECB, CBC, GCM", HttpStatus.BAD_REQUEST);
            }

            // 验证IV参数（非ECB模式需要IV）
            if (!"ECB".equalsIgnoreCase(mode)) {
                validationError = validateParameter(iv, "iv");
                if (validationError != null) return validationError;
            }

            String decryptedData = sm4Service.decrypt(encryptedData, key, mode, iv);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("encryptedData", encryptedData);
            response.put("decryptedData", decryptedData);
            response.put("mode", mode.toUpperCase());
            if (!"ECB".equalsIgnoreCase(mode)) {
                response.put("iv", iv);
            }
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return createErrorResponse(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            // 记录详细异常信息用于调试，但不暴露给客户端
            e.printStackTrace();
            return createErrorResponse("Failed to decrypt data", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * 生成SM4密钥
     * @return 生成的16字节密钥（十六进制格式）
     */
    @PostMapping("/key")
    public ResponseEntity<Map<String, Object>> generateKey() {
        try {
            // 生成16字节（128位）的随机密钥
            byte[] key = new byte[16];
            new java.security.SecureRandom().nextBytes(key);
            String keyHex = org.bouncycastle.util.encoders.Hex.toHexString(key);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("key", keyHex);
            response.put("length", key.length);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace();
            return createErrorResponse("Failed to generate key", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * 生成初始化向量(IV)
     * @param mode 工作模式
     * @return 生成的IV（十六进制格式）
     */
    @PostMapping("/iv")
    public ResponseEntity<Map<String, Object>> generateIv(@RequestParam(defaultValue = "CBC") String mode) {
        try {
            if (!isValidMode(mode)) {
                return createErrorResponse("Invalid mode. Supported modes: ECB, CBC, GCM", HttpStatus.BAD_REQUEST);
            }

            byte[] iv;
            if ("GCM".equalsIgnoreCase(mode)) {
                // GCM模式需要12字节IV
                iv = new byte[12];
            } else if ("CBC".equalsIgnoreCase(mode)) {
                // CBC模式需要16字节IV
                iv = new byte[16];
            } else {
                // ECB模式不需要IV
                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("mode", "ECB");
                response.put("message", "ECB mode does not require IV");
                return ResponseEntity.ok(response);
            }

            new java.security.SecureRandom().nextBytes(iv);
            String ivHex = org.bouncycastle.util.encoders.Hex.toHexString(iv);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("iv", ivHex);
            response.put("mode", mode.toUpperCase());
            response.put("length", iv.length);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace();
            return createErrorResponse("Failed to generate IV", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * 验证工作模式是否有效
     * @param mode 工作模式
     * @return 是否有效
     */
    private boolean isValidMode(String mode) {
        return mode != null && ("ECB".equalsIgnoreCase(mode) || "CBC".equalsIgnoreCase(mode) || "GCM".equalsIgnoreCase(mode));
    }
}