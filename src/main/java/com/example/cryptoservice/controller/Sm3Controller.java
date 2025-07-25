package com.example.cryptoservice.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.cryptoservice.service.Sm3Service;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/sm3")
public class Sm3Controller {

    private final Sm3Service sm3Service;

    public Sm3Controller(Sm3Service sm3Service) {
        this.sm3Service = sm3Service;
    }

    /**
     * 计算输入字符串的SM3哈希值
     * @param request 请求体，包含"input"字段
     * @return 包含哈希结果的响应
     */
    @PostMapping("/hash")
    public ResponseEntity<Map<String, String>> computeHash(@RequestBody Map<String, String> request) {
        try {
            String input = request.get("input");
            if (input == null || input.isEmpty()) {
                Map<String, String> error = new HashMap<>();
                error.put("error", "Input parameter 'input' is required");
                return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
            }

            String hashResult = sm3Service.computeSm3Hash(input);
            Map<String, String> response = new HashMap<>();
            response.put("input", input);
            response.put("sm3Hash", hashResult);

            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}