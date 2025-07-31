package com.example.cryptoservice.controller;

import com.example.cryptoservice.service.Aes256Service;
import com.example.cryptoservice.dto.CryptoRequest;
import com.example.cryptoservice.dto.CryptoResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * AES256加密控制器
 * 
 * 提供国际算法AES256对称加密的REST API接口，支持ECB、CBC、GCM三种工作模式。
 * 
 * @author Crypto Service Team
 * @version 1.0
 */
@RestController
@RequestMapping("/api/aes256")
public class Aes256Controller {

    @Autowired
    private Aes256Service aes256Service;

    /**
     * AES256加密接口
     * 
     * 使用指定的密钥和工作模式对数据进行AES256加密。
     * 
     * @param request 包含明文、密钥、工作模式和初始化向量的请求对象
     * @return 包含加密结果的响应对象
     */
    @PostMapping("/encrypt")
    public ResponseEntity<CryptoResponse> encrypt(@RequestBody CryptoRequest request) {
        try {
            String encrypted;
            
            // 根据工作模式选择加密方法
            switch (request.getMode().toUpperCase()) {
                case "ECB":
                    encrypted = aes256Service.encrypt(request.getData(), request.getKey(), "ECB", null);
                    break;
                case "CBC":
                    if (request.getIv() == null) {
                        return ResponseEntity.badRequest().body(
                            new CryptoResponse("error", "IV is required for CBC mode", null, null)
                        );
                    }
                    encrypted = aes256Service.encrypt(request.getData(), request.getKey(), "CBC", request.getIv());
                    break;
                case "GCM":
                    if (request.getIv() == null) {
                        return ResponseEntity.badRequest().body(
                            new CryptoResponse("error", "IV is required for GCM mode", null, null)
                        );
                    }
                    encrypted = aes256Service.encrypt(request.getData(), request.getKey(), "GCM", request.getIv());
                    break;
                default:
                    return ResponseEntity.badRequest().body(
                        new CryptoResponse("error", "Unsupported mode: " + request.getMode(), null, null)
                    );
            }
            
            return ResponseEntity.ok(new CryptoResponse("success", "Encryption successful", encrypted, null));
            
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                new CryptoResponse("error", e.getMessage(), null, null)
            );
        }
    }

    /**
     * AES256解密接口
     * 
     * 使用指定的密钥和工作模式对数据进行AES256解密。
     * 
     * @param request 包含密文、密钥、工作模式和初始化向量的请求对象
     * @return 包含解密结果的响应对象
     */
    @PostMapping("/decrypt")
    public ResponseEntity<CryptoResponse> decrypt(@RequestBody CryptoRequest request) {
        try {
            String decrypted;
            
            // 根据工作模式选择解密方法
            switch (request.getMode().toUpperCase()) {
                case "ECB":
                    decrypted = aes256Service.decrypt(request.getData(), request.getKey(), "ECB", null);
                    break;
                case "CBC":
                    if (request.getIv() == null) {
                        return ResponseEntity.badRequest().body(
                            new CryptoResponse("error", "IV is required for CBC mode", null, null)
                        );
                    }
                    decrypted = aes256Service.decrypt(request.getData(), request.getKey(), "CBC", request.getIv());
                    break;
                case "GCM":
                    if (request.getIv() == null) {
                        return ResponseEntity.badRequest().body(
                            new CryptoResponse("error", "IV is required for GCM mode", null, null)
                        );
                    }
                    decrypted = aes256Service.decrypt(request.getData(), request.getKey(), "GCM", request.getIv());
                    break;
                default:
                    return ResponseEntity.badRequest().body(
                        new CryptoResponse("error", "Unsupported mode: " + request.getMode(), null, null)
                    );
            }
            
            return ResponseEntity.ok(new CryptoResponse("success", "Decryption successful", decrypted, null));
            
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                new CryptoResponse("error", e.getMessage(), null, null)
            );
        }
    }

    /**
     * 生成AES256密钥
     * 
     * 生成符合AES256要求的32字节随机密钥。
     * 
     * @return 包含密钥的响应对象
     */
    @GetMapping("/key")
    public ResponseEntity<CryptoResponse> generateKey() {
        try {
            byte[] key = aes256Service.generateKey();
            String keyHex = bytesToHex(key);
            return ResponseEntity.ok(new CryptoResponse("success", "Key generated successfully", keyHex, null));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                new CryptoResponse("error", e.getMessage(), null, null)
            );
        }
    }

    /**
     * 生成初始化向量
     * 
     * 根据指定的工作模式生成合适的初始化向量。
     * 
     * @param mode 工作模式（CBC或GCM）
     * @return 包含初始化向量的响应对象
     */
    @GetMapping("/iv/{mode}")
    public ResponseEntity<CryptoResponse> generateIv(@PathVariable String mode) {
        try {
            if (!"CBC".equalsIgnoreCase(mode) && !"GCM".equalsIgnoreCase(mode)) {
                return ResponseEntity.badRequest().body(
                    new CryptoResponse("error", "IV generation only supported for CBC and GCM modes", null, null)
                );
            }
            
            byte[] iv = aes256Service.generateIv(mode.toUpperCase());
            String ivHex = bytesToHex(iv);
            return ResponseEntity.ok(new CryptoResponse("success", "IV generated successfully for " + mode.toUpperCase(), ivHex, null));
            
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(
                new CryptoResponse("error", e.getMessage(), null, null)
            );
        }
    }

    /**
     * 字节数组转十六进制字符串
     * 
     * @param bytes 字节数组
     * @return 十六进制字符串
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}