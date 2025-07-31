package com.example.cryptoservice.dto;

/**
 * 加密/解密响应DTO
 * 
 * 用于向客户端返回加密或解密操作的结果。
 */
public class CryptoResponse {
    
    private String status;
    private String message;
    private String data;
    private String error;

    public CryptoResponse() {}

    public CryptoResponse(String status, String message, String data, String error) {
        this.status = status;
        this.message = message;
        this.data = data;
        this.error = error;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }
}