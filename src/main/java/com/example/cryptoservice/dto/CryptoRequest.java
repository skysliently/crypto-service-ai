package com.example.cryptoservice.dto;

/**
 * 加密/解密请求DTO
 * 
 * 用于接收客户端的加密或解密请求参数。
 */
public class CryptoRequest {
    
    private String data;
    private String key;
    private String mode;
    private String iv;

    public CryptoRequest() {}

    public CryptoRequest(String data, String key, String mode, String iv) {
        this.data = data;
        this.key = key;
        this.mode = mode;
        this.iv = iv;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }
}