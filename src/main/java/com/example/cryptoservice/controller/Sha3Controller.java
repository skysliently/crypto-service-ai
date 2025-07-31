package com.example.cryptoservice.controller;

import com.example.cryptoservice.service.Sha3Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * SHA-3系列算法REST控制器
 * 
 * 提供SHA-3系列哈希算法的RESTful API接口，支持多种算法选择和参数验证。
 * SHA-3基于Keccak算法，采用海绵结构设计，具有更好的抗量子计算能力。
 * 
 * @author Assistant
 * @since 1.0
 */
@RestController
@RequestMapping("/api/sha3")
public class Sha3Controller {

    private final Sha3Service sha3Service;

    @Autowired
    public Sha3Controller(Sha3Service sha3Service) {
        this.sha3Service = sha3Service;
    }

    /**
     * 计算SHA3-256哈希值
     * 
     * @param request 包含输入数据的请求体
     * @return 包含哈希结果的响应
     */
    @PostMapping("/sha3-256")
    public ResponseEntity<Map<String, String>> computeSha3_256(@RequestBody Map<String, String> request) {
        return computeHash(request, "SHA3-256", (input) -> sha3Service.sha3_256(input));
    }

    /**
     * 计算SHA3-512哈希值
     * 
     * @param request 包含输入数据的请求体
     * @return 包含哈希结果的响应
     */
    @PostMapping("/sha3-512")
    public ResponseEntity<Map<String, String>> computeSha3_512(@RequestBody Map<String, String> request) {
        return computeHash(request, "SHA3-512", (input) -> sha3Service.sha3_512(input));
    }

    /**
     * 计算SHA3-384哈希值
     * 
     * @param request 包含输入数据的请求体
     * @return 包含哈希结果的响应
     */
    @PostMapping("/sha3-384")
    public ResponseEntity<Map<String, String>> computeSha3_384(@RequestBody Map<String, String> request) {
        return computeHash(request, "SHA3-384", (input) -> sha3Service.sha3_384(input));
    }

    /**
     * 计算SHA3-224哈希值
     * 
     * @param request 包含输入数据的请求体
     * @return 包含哈希结果的响应
     */
    @PostMapping("/sha3-224")
    public ResponseEntity<Map<String, String>> computeSha3_224(@RequestBody Map<String, String> request) {
        return computeHash(request, "SHA3-224", (input) -> sha3Service.sha3_224(input));
    }

    /**
     * 通用哈希计算接口，支持动态选择SHA-3算法
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
                algorithm = "SHA3-256"; // 默认算法
            }

            String hashResult = sha3Service.computeHash(input, algorithm);
            
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
     * 获取支持的SHA-3算法列表
     * 
     * @return 支持的算法列表及描述信息
     */
    @GetMapping("/algorithms")
    public ResponseEntity<Map<String, Object>> getSupportedAlgorithms() {
        Map<String, Object> response = new HashMap<>();
        response.put("algorithms", new String[]{"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"});
        response.put("descriptions", new String[]{
                "224-bit Keccak-based secure hash algorithm",
                "256-bit Keccak-based secure hash algorithm (recommended)",
                "384-bit Keccak-based secure hash algorithm",
                "512-bit Keccak-based secure hash algorithm"
        });
        response.put("features", new String[]{
                "Quantum-resistant design",
                "Sponge construction",
                "Arbitrary output length support",
                "Hardware acceleration support"
        });
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    /**
     * 比较SHA-2和SHA-3算法的性能特点
     * 
     * @return 算法比较信息
     */
    @GetMapping("/comparison")
    public ResponseEntity<Map<String, Object>> getAlgorithmComparison() {
        Map<String, Object> response = new HashMap<>();
        
        Map<String, String> sha2Info = new HashMap<>();
        sha2Info.put("design", "Merkle-Damgård construction");
        sha2Info.put("security", "Collision resistant, but vulnerable to length extension attacks");
        sha2Info.put("performance", "Fast software implementation");
        
        Map<String, String> sha3Info = new HashMap<>();
        sha3Info.put("design", "Sponge construction");
        sha3Info.put("security", "Collision resistant, length extension resistant, quantum-resistant");
        sha3Info.put("performance", "Excellent hardware acceleration, competitive software performance");
        
        response.put("sha2", sha2Info);
        response.put("sha3", sha3Info);
        response.put("recommendation", "Use SHA3-256 for new applications requiring future-proof security");
        
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