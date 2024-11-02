# Fernet key database for pem

### 基于Fernet算法的pem证书私钥数据库

#### Feature

- 原生支持简体中文
- 仅明文储存盐和密文
- 使用Fernet算法加密
- 输入密码时使用 `*` 脱敏处理
- 支持根据文件后缀批量导入私钥
- 不同的私钥导入时可以使用不同的密码
- 虽然是针对pem文件进行的优化，但理论上其他类型的文件也能加密

#### Build

```
pip install -r requirements.txt
pyinstaller -F main.py -i Nya-WSL.ico
```
