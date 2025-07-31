package com.example.cryptoservice.controller;

import com.example.cryptoservice.service.Sha2Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * SHA-2系列算法REST控制器
 * 
 * 提供SHA-2系列哈希算法的RESTful API接口，支持多种算法选择和参数验证。
 * 
 * @author Assistant
 * @since 1.0
 */
@RestController
@RequestMapping("/api/sha2")
public class Sha2Controller {

    private final Sha2Service sha2Service;

    @Autowired
    public Sha2Controller(Sha2Service sha2Service) {
        this.sha2Service = sha2Service;
    }

    /**
     * 计算SHA-256哈希值
     * 
     * @param request 包含输入数据的请求体
     * @return 包含哈希结果的响应
     */
    @PostMapping("/sha256")
    public ResponseEntity<Map<String, String>> computeSha256(@RequestBody Map<String, String> request) {
        return computeHash(request, "SHA-256", (input) -> sha2Service.sha256(input));
    }

    /**
     * 计算SHA-512哈希值
     * 
     * @param request 包含输入数据的请求体
     * @return 包含哈希结果的响应
     */
    @PostMapping("/sha512")
    public ResponseEntity<Map<String, String>> computeSha512(@RequestBody Map<String, String> request) {
        return computeHash(request, "SHA-512", (input) -> sha2Service.sha512(input));
    }

    /**
     * 计算SHA-384哈希值
     * 
     * @param request 包含输入数据的请求体
     * @return 包含哈希结果的响应
     */
    @PostMapping("/sha384")
    public ResponseEntity<Map<String, String>> computeSha384(@RequestBody Map<String, String> request) {
        return computeHash(request, "SHA-384", (input) -> sha2Service.sha384(input));
    }

    /**
     * 计算SHA-224哈希值
     * 
     * @param request 包含输入数据的请求体
     * @return 包含哈希结果的响应
     */
    @PostMapping("/sha224")
    public ResponseEntity<Map<String, String>> computeSha224(@RequestBody Map<String, String> request) {
        return computeHash(request, "SHA-224", (input) -> sha2Service.sha224(input));
    }

    /**
     * 通用哈希计算接口，支持动态选择SHA-2算法
     * 
     * @param request 包含输入数据和算法的请求体
     * @return 包含哈希结果的响应
     */
    @PostMapping("/hash")
    public ResponseEntity<Map<String, String>> computeHash(@RequestBody Map<String, String> request) {
        try {
            String input = request.get("input");
            String algorithm = request.get("algorithm");

            if (input == null || input.isEmpty()) {
                return createErrorResponse("Input parameter 'input' is required");
            }

            if (algorithm == null || algorithm.trim().isEmpty()) {
                algorithm = "SHA-256"; // 默认算法
            }

            String hashResult = sha2Service.computeHash(input, algorithm);
            
            Map<String, String> response = new HashMap<>();
            response.put("input", input);
            response.put("algorithm", algorithm);
            response.put("hash", hashResult);
            response.put("hashLength", String.valueOf(hashResult.length() / 2)); // 字节长度

            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (IllegalArgumentException e) {
            return createErrorResponse(e.getMessage());
        } catch (Exception e) {
            return createErrorResponse("Internal server error: " + e.getMessage());
        }
    }

    /**
     * 获取支持的SHA-2算法列表
     * 
     * @return 支持的算法列表
     */
    @GetMapping("/algorithms")
    public ResponseEntity<Map<String, Object>> getSupportedAlgorithms() {
        Map<String, Object> response = new HashMap<>();
        response.put("algorithms", new String[]{"SHA-224", "SHA-256", "SHA-384", "SHA-512"});
        response.put("descriptions", new String[]{
                "224-bit secure hash algorithm",
                "256-bit secure hash algorithm (most common)",
                "384-bit secure hash algorithm",
                "512-bit secure hash algorithm"
        });
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    /**
     * 通用哈希计算辅助方法
     * 
     * @param request 请求体
     * @param algorithmName 算法名称
     * @param hashFunction 哈希计算函数
     * @return 响应实体
     */
    private ResponseEntity<Map<String, String>> computeHash(
            Map<String, String> request, 
            String algorithmName,
            java.util.function.Function<String, String> hashFunction) {
        try {
            String input = request.get("input");
            if (input == null || input.isEmpty()) {
                return createErrorResponse("Input parameter 'input' is required");
            }

            String hashResult = hashFunction.apply(input);
            
            Map<String, String> response = new HashMap<>();
            response.put("input", input);
            response.put("algorithm", algorithmName);
            response.put("hash", hashResult);
            response.put("hashLength", String.valueOf(hashResult.length() / 2)); // 字节长度

            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            return createErrorResponse("Internal server error: " + e.getMessage());
        }
    }

    /**
     * 创建错误响应
     * 
     * @param errorMessage 错误消息
     * @return 错误响应实体
     */
    private ResponseEntity<Map<String, String>> createErrorResponse(String errorMessage) {
        Map<String, String> error = new HashMap<>();
        error.put("error", errorMessage);
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }
}