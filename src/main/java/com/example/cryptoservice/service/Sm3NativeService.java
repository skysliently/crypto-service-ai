package com.example.cryptoservice.service;

import org.springframework.stereotype.Service;
import java.nio.charset.StandardCharsets;

/**
 * SM3密码杂凑算法原生Java实现服务类
 * 
 * SM3是中国国家密码管理局发布的密码杂凑算法，输出长度为256位（32字节）。
 * 该实现遵循GM/T 0004-2012《SM3密码杂凑算法》标准，完全使用Java原生代码实现，
 * 不依赖任何第三方加密库。
 * 
 * SM3算法主要包含以下步骤：
 * 1. 消息填充：确保消息长度满足特定条件
 * 2. 消息扩展：将512位消息分组扩展为多个32位字
 * 3. 压缩函数：通过64轮迭代处理，生成最终的杂凑值
 * 
 * 该服务类提供字符串和字节数组两种输入接口，输出为十六进制编码的哈希值。
 * 
 * @author Assistant
 * @since 1.0
 */
@Service
public class Sm3NativeService {

    // SM3常量参数
    // SM3算法常量定义（符合GM/T 0004-2012标准）
    /** SM3初始向量值 */
    private static final int[] IV = {0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E};
    /** 0≤j≤15轮常量 */
    private static final int T1 = 0x79CC4519;
    /** 16≤j≤63轮常量 */
    private static final int T2 = 0x7A879D8A;
    /** 扩展字数组长度 */
    private static final int WORD_COUNT = 68;
    /** 压缩轮数 */
    private static final int ROUND_COUNT = 64;
    /** 消息长度字段大小（字节） */
    private static final int LENGTH_FIELD_SIZE = 8;

    /**
     * 计算输入字符串的SM3哈希值（原生Java实现）
     * 
     * 使用UTF-8编码将输入字符串转换为字节数组，然后计算其SM3哈希值。
     * 
     * @param input 输入字符串，不能为null
     * @return 十六进制编码的SM3哈希值（64个字符）
     * @throws IllegalArgumentException 当输入字符串为null时抛出
     */
    public String computeSm3Hash(String input) {
        if (input == null) {
            throw new IllegalArgumentException("Input string cannot be null");
        }

        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        return computeSm3Hash(bytes);
    }

    /**
     * 计算输入字节数组的SM3哈希值（原生Java实现）
     * 
     * 对输入的字节数组执行完整的SM3哈希计算流程，包括消息填充、扩展和压缩。
     * 
     * @param inputBytes 输入字节数组，不能为null
     * @return 十六进制编码的SM3哈希值（64个字符）
     * @throws IllegalArgumentException 当输入字节数组为null时抛出
     */
    public String computeSm3Hash(byte[] inputBytes) {
        if (inputBytes == null) {
            throw new IllegalArgumentException("Input byte array cannot be null");
        }

        // 消息填充
        byte[] paddedMsg = padMessage(inputBytes);
        int n = paddedMsg.length / 64;

        // 初始化IV作为初始链变量
        int[] cv = IV.clone();

        // 迭代处理每个消息分组
        for (int i = 0; i < n; i++) {
            byte[] b = new byte[64];
            System.arraycopy(paddedMsg, i * 64, b, 0, 64);
            int[][] expanded = expand(b);
            int[] newCv = compress(cv, expanded); // 压缩函数返回新的链变量
            cv = newCv;
        }

        // 结果转换为十六进制字符串
        return intArrayToHexString(cv);
    }

    /**
     * 消息填充（符合SM3规范GM/T 0004-2012）
     * 
     * 按照SM3标准进行消息填充，确保填充后的消息长度满足特定条件：
     * 1. 追加一个'1'位
     * 2. 追加k个'0'位，使总长度 ≡ 448 mod 512
     * 3. 追加64位消息长度（大端序）
     * 
     * @param msg 原始消息字节数组
     * @return 填充后的消息字节数组
     */
    private byte[] padMessage(byte[] msg) {
        int len = msg.length;
        long bitLen = (long) len * 8;
        
        // 修正填充长度计算，符合GM/T 0004-2012标准
        int k = (448 - (int)(bitLen % 512) - 1 + 512) % 512;
        
        int paddedLen = len + 1 + (k / 8) + LENGTH_FIELD_SIZE;
        byte[] padded = new byte[paddedLen];
        System.arraycopy(msg, 0, padded, 0, len);
        
        // 填充1位
        padded[len] = (byte) 0x80;
        
        // 填充64位消息长度（大端序）
        for (int i = 0; i < 8; i++) {
            padded[paddedLen - 8 + i] = (byte) (bitLen >>> (8 * (7 - i)));
        }
        
        return padded;
    }

    /**
     * 消息扩展
     * 
     * 将512位消息分组扩展为68个32位字(W数组)和64个32位字(W1数组)，
     * 用于后续的压缩函数处理。
     * 
     * @param b 512位消息分组字节数组（64字节）
     * @return 包含扩展字数组的二维数组，[0]为W数组，[1]为W1数组
     */
    private int[][] expand(byte[] b) {
        int[] w = new int[68];
        int[] w1 = new int[64];

        // 将消息分组转换为32位整数（大端序）
        for (int i = 0; i < 16; i++) {
            w[i] = ((b[i * 4] & 0xFF) << 24) | ((b[i * 4 + 1] & 0xFF) << 16) |
                   ((b[i * 4 + 2] & 0xFF) << 8) | (b[i * 4 + 3] & 0xFF);
        }

        // 扩展生成W[16..67]，修正P1置换函数参数顺序
        for (int i = 16; i < WORD_COUNT; i++) {
            w[i] = P1(w[i - 16] ^ w[i - 9] ^ rotateLeft(w[i - 3], 15)) ^ rotateLeft(w[i - 13], 7) ^ w[i - 6];
        }

        // 生成W1[0..63]
        for (int i = 0; i < ROUND_COUNT; i++) {
            w1[i] = w[i] ^ w[i + 4];
        }

        return new int[][]{w, w1};
    }

    /**
     * 压缩函数
     * 
     * SM3算法的核心部分，通过64轮迭代处理消息分组，更新链变量。
     * 每一轮使用不同的布尔函数和轮常量进行计算。
     * 
     * @param cv 当前链变量数组（8个32位整数）
     * @param w 包含扩展字数组的二维数组
     * @return 更新后的链变量数组
     */
    private int[] compress(int[] cv, int[][] w) {
        int[] W = w[0];
        int[] W1 = w[1];
        int A = cv[0], B = cv[1], C = cv[2], D = cv[3];
        int E = cv[4], F = cv[5], G = cv[6], H = cv[7];

        for (int j = 0; j < ROUND_COUNT; j++) {
            int Tj = (j < 16) ? T1 : T2;
            int SS1 = rotateLeft((rotateLeft(A, 12) + E + rotateLeft(Tj, j)), 7);
            int SS2 = SS1 ^ rotateLeft(A, 12);
            int TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            int TT2 = GG(E, F, G, j) + H + SS1 + W[j];
            int newA = TT1;
            int newE = P0(TT2);
            int newD = C;
            int newC = rotateLeft(B, 9);
            int newB = A;
            int newH = G;
            int newG = rotateLeft(F, 19);
            int newF = E;

            A = newA;
            B = newB;
            C = newC;
            D = newD;
            E = newE;
            F = newF;
            G = newG;
            H = newH;
        }

        int[] newCv = new int[8];
        newCv[0] = A ^ cv[0];
        newCv[1] = B ^ cv[1];
        newCv[2] = C ^ cv[2];
        newCv[3] = D ^ cv[3];
        newCv[4] = E ^ cv[4];
        newCv[5] = F ^ cv[5];
        newCv[6] = G ^ cv[6];
        newCv[7] = H ^ cv[7];
        return newCv;
    }

    /**
     * 布尔函数FF
     * 
     * SM3算法中使用的布尔函数，根据轮数j采用不同的计算方式：
     * - j ∈ [0, 15]：FF_j(X,Y,Z) = X XOR Y XOR Z
     * - j ∈ [16, 63]：FF_j(X,Y,Z) = (X AND Y) OR (X AND Z) OR (Y AND Z)
     * 
     * @param x 第一个输入参数
     * @param y 第二个输入参数
     * @param z 第三个输入参数
     * @param j 当前轮数
     * @return 布尔函数计算结果
     */
    private int FF(int x, int y, int z, int j) {
        if (j < 16) {
            return x ^ y ^ z;
        } else {
            return (x & y) | (x & z) | (y & z);
        }
    }

    /**
     * 布尔函数GG
     * 
     * SM3算法中使用的布尔函数，根据轮数j采用不同的计算方式：
     * - j ∈ [0, 15]：GG_j(X,Y,Z) = X XOR Y XOR Z
     * - j ∈ [16, 63]：GG_j(X,Y,Z) = (X AND Y) OR ((NOT X) AND Z)
     * 
     * @param x 第一个输入参数
     * @param y 第二个输入参数
     * @param z 第三个输入参数
     * @param j 当前轮数
     * @return 布尔函数计算结果
     */
    private int GG(int x, int y, int z, int j) {
        if (j < 16) {
            return x ^ y ^ z;
        } else {
            return (x & y) | (~x & z);
        }
    }

    /**
     * 置换函数P0
     * 
     * SM3算法中使用的置换函数，用于消息扩展过程。
     * P0(X) = X XOR (X <<< 9) XOR (X <<< 17)
     * 
     * @param x 32位输入值
     * @return 置换函数计算结果
     */
    private int P0(int x) {
        return x ^ rotateLeft(x, 9) ^ rotateLeft(x, 17);
    }

    /**
     * 置换函数P1
     * 
     * SM3算法中使用的置换函数，用于消息扩展过程。
     * P1(X) = X XOR (X <<< 15) XOR (X <<< 23)
     * 
     * @param x 32位输入值
     * @return 置换函数计算结果
     */
    private int P1(int x) {
        return x ^ rotateLeft(x, 15) ^ rotateLeft(x, 23);
    }

    /**
     * 循环左移
     * 
     * 对32位整数进行循环左移操作。
     * 
     * @param x 待移位的32位整数
     * @param n 左移位数
     * @return 循环左移后的结果
     */
    private int rotateLeft(int x, int n) {
        return (x << n) | (x >>> (32 - n));
    }

    /**
     * 将int数组转换为十六进制字符串
     * 
     * 将包含32位整数的数组转换为十六进制字符串表示。
     * 
     * @param arr 包含32位整数的数组
     * @return 十六进制字符串
     */
    private String intArrayToHexString(int[] arr) {
        StringBuilder sb = new StringBuilder();
        for (int num : arr) {
            sb.append(String.format("%08x", num));
        }
        return sb.toString();
    }
}