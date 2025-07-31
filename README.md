# 全功能加密服务API

一个基于Spring Boot的现代化、全功能加密服务API，提供对称加密、非对称加密和哈希算法的完整解决方案。

## 🎯 项目简介

本项目是一个加密服务，提供以下三大类加密功能：

### 🔐 对称加密算法
- **AES-256**：支持ECB、CBC、GCM模式，256位密钥长度
- **SM4**：支持ECB、CBC、GCM模式，128位密钥长度，中国商用密码算法

### 🔑 非对称加密算法
- **RSA**：支持1024、2048、4096位密钥长度，提供密钥对生成、加密、解密、签名、验证
- **SM2**：中国商用密码椭圆曲线算法，支持密钥对生成、加密、解密、签名、验证

### 🔒 哈希算法
- **SHA-2系列**：SHA-224、SHA-256、SHA-384、SHA-512
- **SHA-3系列**：SHA3-224、SHA3-256、SHA3-384、SHA3-512（基于Keccak算法）
- **SM3**：中国商用密码哈希算法

## 🤖 AI生成信息

本项目由AI工具**Trae AI**智能生成，使用了以下技术：

- **AI IDE**：Trae AI（世界领先的AI驱动集成开发环境）
- **大语言模型**：集成了先进的AI模型进行代码生成和优化
- **生成方式**：通过自然语言描述需求，AI自动生成完整项目架构、代码实现和测试用例

## 🚀 快速开始

### 环境要求
- Java 17 或更高版本
- Maven 3.6+
- Spring Boot 3.x

### 安装依赖
```bash
mvn clean install
```

### 运行应用
```bash
# 开发模式
mvn spring-boot:run

# 生产模式
java -jar target/sm3-service-*.jar
```

### 访问API文档
启动应用后，访问：http://localhost:8080/swagger-ui.html

## 📖 API使用指南

### 1. SHA-2算法API

#### 专用端点（快速调用）
- **SHA-256**: POST `/api/sha2/sha256`
- **SHA-512**: POST `/api/sha2/sha512`
- **SHA-384**: POST `/api/sha2/sha384`
- **SHA-224**: POST `/api/sha2/sha224`

#### 通用端点（动态算法选择）
- **通用哈希**: POST `/api/sha2/hash`

#### 计算SHA-256哈希
```bash
curl -X POST http://localhost:8080/api/sha2/sha256 \
  -H "Content-Type: application/json" \
  -d '{"input":"Hello World"}'
```

#### 支持的算法
- SHA-224
- SHA-256
- SHA-384
- SHA-512

#### 获取算法信息
```bash
curl -X GET http://localhost:8080/api/sha2/algorithms
```

### 2. SHA-3算法API

#### 专用端点（快速调用）
- **SHA3-256**: POST `/api/sha3/sha3-256`
- **SHA3-512**: POST `/api/sha3/sha3-512`
- **SHA3-384**: POST `/api/sha3/sha3-384`
- **SHA3-224**: POST `/api/sha3/sha3-224`

#### 通用端点（动态算法选择）
- **通用哈希**: POST `/api/sha3/hash`

#### 计算SHA3-256哈希
```bash
curl -X POST http://localhost:8080/api/sha3/sha3-256 \
  -H "Content-Type: application/json" \
  -d '{"input":"Hello World"}'
```

#### 支持的算法
- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512

#### 获取算法信息
```bash
curl -X GET http://localhost:8080/api/sha3/algorithms
```

#### 算法对比信息
```bash
curl -X GET http://localhost:8080/api/sha3/comparison
```

### 3. SM3算法API

#### 专用端点
- **SM3哈希**: POST `/api/sm3/hash`

#### 计算SM3哈希
```bash
curl -X POST http://localhost:8080/api/sm3/hash \
  -H "Content-Type: application/json" \
  -d '{"input":"Hello World"}'
```

### 4. 对称加密算法

#### AES-256加密/解密
- **加密**: `POST /api/aes256/encrypt`
- **解密**: `POST /api/aes256/decrypt`
- **生成密钥**: `POST /api/aes256/key`
- **生成IV**: `POST /api/aes256/iv`
- **支持模式**: ECB, CBC, GCM
- **密钥长度**: 256位
- **示例**:
```bash
# 加密
curl -X POST http://localhost:8080/api/aes256/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plainText":"Hello World","key":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","mode":"CBC","iv":"0123456789abcdef0123456789abcdef"}'

# 生成密钥
curl -X POST http://localhost:8080/api/aes256/key

# 生成IV
curl -X POST http://localhost:8080/api/aes256/iv?mode=CBC
```

#### SM4加密/解密
- **加密**: `POST /api/sm4/encrypt`
- **解密**: `POST /api/sm4/decrypt`
- **生成密钥**: `POST /api/sm4/key`
- **生成IV**: `POST /api/sm4/iv`
- **支持模式**: ECB, CBC, GCM
- **密钥长度**: 128位
- **示例**:
```bash
# 加密
curl -X POST http://localhost:8080/api/sm4/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plainText":"Hello World","key":"0123456789abcdef0123456789abcdef","mode":"CBC","iv":"0123456789abcdef0123456789abcdef"}'

# 生成密钥
curl -X POST http://localhost:8080/api/sm4/key

# 生成IV
curl -X POST http://localhost:8080/api/sm4/iv?mode=CBC
```

### 5. 非对称加密算法

#### RSA加密/解密
- **生成密钥对**: `POST /api/rsa/generate-key-pair`
- **公钥加密**: `POST /api/rsa/encrypt`
- **私钥解密**: `POST /api/rsa/decrypt`
- **私钥加密**: `POST /api/rsa/encrypt-with-private`
- **公钥解密**: `POST /api/rsa/decrypt-with-public`
- **密钥长度**: 1024, 2048, 4096位（默认2048位）
- **示例**:
```bash
# 生成密钥对
curl -X POST http://localhost:8080/api/rsa/generate-key-pair \
  -H "Content-Type: application/json" \
  -d '{"keySize":2048}'

# 公钥加密
curl -X POST http://localhost:8080/api/rsa/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plainText":"Hello World","publicKey":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."}'

# 私钥解密
curl -X POST http://localhost:8080/api/rsa/decrypt \
  -H "Content-Type: application/json" \
  -d '{"encryptedData":"a1b2c3...","privateKey":"MIIEvQIBADANBgkqhkiG9w0BAQEFAASC..."}'
```

#### SM2加密/解密
- **生成密钥对**: `POST /api/sm2/keypair`
- **签名**: `POST /api/sm2/sign`
- **验证签名**: `POST /api/sm2/verify`
- **加密**: `POST /api/sm2/encrypt`
- **解密**: `POST /api/sm2/decrypt`
- **示例**:
```bash
# 生成密钥对
curl -X POST http://localhost:8080/api/sm2/keypair

# 签名
curl -X POST http://localhost:8080/api/sm2/sign \
  -H "Content-Type: application/json" \
  -d '{"plainText":"Hello World","privateKey":"..."}'

# 验证签名
curl -X POST http://localhost:8080/api/sm2/verify \
  -H "Content-Type: application/json" \
  -d '{"plainText":"Hello World","signature":"...","publicKey":"..."}'

# 加密
curl -X POST http://localhost:8080/api/sm2/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plainText":"Hello World","publicKey":"..."}'

# 解密
curl -X POST http://localhost:8080/api/sm2/decrypt \
  -H "Content-Type: application/json" \
  -d '{"encryptedData":"...","privateKey":"..."}'
```

## 🔧 配置说明

### 应用配置 (application.yml)
```yaml
server:
  port: 8080

spring:
  application:
    name: sm3-service
  
logging:
  level:
    com.example.cryptoservice: INFO
```

### Maven配置 (pom.xml)
项目已配置以下关键依赖：
- Spring Boot Starter Web
- Spring Boot Starter Test
- Bouncy Castle加密库
- Swagger/OpenAPI文档

## 🧪 测试

### 运行所有测试
```bash
mvn test
```

### 运行特定测试
```bash
# 运行SHA-2测试
mvn test -Dtest=Sha2ServiceTest

# 运行SHA-3测试
mvn test -Dtest=Sha3ServiceTest

# 运行SM3测试
mvn test -Dtest=Sm3NativeServiceTest
```

## 📊 性能特点

- **高性能**：使用原生加密库实现，性能优异
- **线程安全**：所有服务均为无状态设计，支持并发访问
- **算法完整**：覆盖国际主流和中国商用密码算法
- **易扩展**：模块化设计，易于添加新算法

## 📋 API响应示例

### 成功响应
```json
{
  "input": "Hello World",
  "algorithm": "SHA-256",
  "hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
  "hashLength": "32"
}
```

### 错误响应
```json
{
  "error": "Input parameter 'input' is required"
}
```

## 🛡️ 错误处理

### 支持的HTTP状态码
- **200 OK**: 请求成功
- **400 Bad Request**: 参数错误
- **500 Internal Server Error**: 服务器内部错误

### 参数验证规则
- 输入不能为空字符串
- 算法名称支持大小写不敏感匹配
- 自动提供默认算法（SHA-2默认为SHA-256，SHA-3默认为SHA3-256）

## 🔒 安全特性

- 输入验证：严格的参数校验和异常处理
- 算法验证：支持算法名称大小写不敏感
- 错误处理：详细的错误信息和HTTP状态码
- 日志记录：完整的操作日志和错误日志

## 📁 项目结构

```
src/
├── main/
│   ├── java/com/example/cryptoservice/
│   │   ├── controller/    # REST API控制器
│   │   ├── service/       # 核心业务逻辑
│   │   ├── model/         # 数据模型
│   │   └── Application.java
│   └── resources/
│       ├── application.yml
│       └── static/
└── test/
    └── java/com/example/cryptoservice/
        └── service/       # 单元测试
```

## 🛠️ 开发指南

### 添加新算法
1. 在对应的服务类中添加新方法
2. 更新控制器API
3. 添加对应的测试用例
4. 更新API文档

### 自定义配置
可以通过application.yml文件配置：
- 服务器端口
- 日志级别
- 算法参数

## 📞 支持与反馈

本项目由AI自动生成，如有问题或建议，欢迎通过以下方式联系：
- 提交Issue
- 发送Pull Request

## 📄 许可证

MIT License - 详见LICENSE文件

---

*本项目由Trae AI智能生成，展示了AI在软件开发中的强大能力。*