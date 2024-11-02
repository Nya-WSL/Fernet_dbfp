import os
import sys
import json
import yaml
import base64
import msvcrt
import platform
from cryptography import fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

version = "1.2.0"
print("----------------------------------------------")
print(f"Fernet key database for pem | Nya-WSL | v{version}")
print("----------------------------------------------")
option = input("1. 导入私钥\n2. 导出私钥\n3. 批量导入\n4. 查看私钥列表\n\n选项: ")
print("-------------------")

if not os.path.exists("config.yml"):
    with open("config.yml", "w") as f:
        f.write("""# 输入密码时使用的密码掩码
# 如果是不被支持的值，则使用默认值
# 默认值: "*"
passwd_mask: "*"

# 盐的文件名，例：salt
# 注意：虽然导入时可以使用不同的密码，但是盐是相同的
# 默认值: "salt"
salt_name: "salt"

# 盐的保存位置，需为绝对路径，例：C:\Users\Nya-WSL\Fernet_dbfp
# 如果是 "cwd"，则盐将保存在程序工作目录中
# 默认值: "cwd"
salt_path: "cwd"

# 密文的文件名，不要写文件后缀，例：pem
# 默认值: "pem"
save_name: "pem"

# 密文的保存位置，需为绝对路径，例：C:\Users\Nya-WSL\Fernet_dbfp
# 如果是 "cwd"，则密文将保存在程序工作目录中
# 默认值: "cwd"
save_path: "cwd"

# 密文保存模式，可选值: "json", "sqlite3（未实现）"
# 默认值: "json"
save_mode: "json"

# PBKDF2HMAC密钥派生函数的迭代次数，必须是整数（int）
# 默认值: 480000
iterations: 480000

# 导入单个文件时是否根据文件名自动生成别称（键名），可选值: True, False
# 默认值: True
auto_import_name: True

# 是否检查更新，可选值: True, False （未实现）
update: True
""")

with open("config.yml", "r") as f:
    config = yaml.load(f, yaml.FullLoader)

chars = []
# password = getpass.getpass("请输入密码: ").encode()
if option != "4":
    print("请输入密码: ", end="")
    while True:
        new_char = msvcrt.getch().decode(encoding='utf-8')
        if new_char in "\r\n":
            break
        elif new_char == "\b":
            if chars:
                del chars[-1]
                msvcrt.putch('\b'.encode(encoding='utf-8'))
                msvcrt.putch(' '.encode(encoding='utf-8'))
                msvcrt.putch('\b'.encode(encoding='utf-8'))
        else:
            chars.append(new_char)
            try:
                msvcrt.putch(config["passwd_mask"].encode(encoding='utf-8'))
            except TypeError:
                msvcrt.putch("*".encode(encoding='utf-8'))
    password = "".join(chars).encode()
    print("")
    if config["salt_path"] == "cwd":
        salt_path = os.getcwd()
    else:
        salt_path = config["salt_path"]
    if os.path.exists(os.path.join(salt_path, config["salt_name"])):
        with open(os.path.join(salt_path, config["salt_name"]), "rb") as f:
            salt = f.read()
    else:
        # 生成盐
        salt = os.urandom(16)
        with open(os.path.join(salt_path, config["salt_name"]), "wb") as f:
            f.write(salt)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=int(config["iterations"]),
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = fernet.Fernet(key)

if config["save_path"] == "cwd":
    pem_path = os.getcwd()
else:
    pem_path = config["save_path"]

read_path = os.path.join(pem_path, f"{config['save_name']}.json")

if option == "1":
    import_path = input("需导入的私钥:")
    if config["save_path"] == "cwd":
        save_path = os.getcwd()
    else:
        save_path = config["save_path"]
    if config["auto_import_name"]:
        save_name = os.path.basename(import_path).split(".")[0]
    else:
        save_name = input("密文别称:")
    file = os.path.join(save_path, f"{config['save_name']}.json")
    with open(import_path, "rb") as pem_bytes:
        pem_text = pem_bytes.read()
    token = f.encrypt(pem_text)
    pem_json = {}
    if os.path.exists(file):
        with open(file, "r", encoding="utf-8") as f:
            pem_json = json.load(f)
    pem_json[save_name] = token.decode()
    with open(file, "w+", encoding="utf-8") as pem_bytes:
        json.dump(pem_json, pem_bytes, ensure_ascii=True, indent=4)
    input("导入完成，按回车键退出...")

if option == "2":
    save_path = input("导出至:")
    with open(read_path, "r", encoding="utf-8") as pem_bytes:
        token = json.load(pem_bytes)
    print("私钥列表：")
    print("-------------------")
    for key,value in token.items():
        print("%s. %s" % (list(token.keys()).index(key) + 1, key))
    print("-------------------")
    save_name = input("需导出的私钥序号:")
    save_name = str(list(token.keys())[int(save_name) - 1])

    try:
        pem_data = f.decrypt(str(token[save_name]).encode()).decode()
    except fernet.InvalidToken:
        input("密码错误！")
        sys.exit("")
    except:
        input("出现错误！")
        sys.exit("")

    with open(os.path.join(save_path, f"{save_name}.old"), "w", encoding="utf-8") as pem_bytes:
        pem_bytes.write(pem_data)
    old = open(os.path.join(save_path, f"{save_name}.old"), "r", encoding="utf-8")
    new = open(os.path.join(save_path, f"{save_name}.pem"), "w", encoding="utf-8")
    for line in old.readlines():
        if line == "\n":
            line = line.strip("\n")
        new.write(line)
    old.close()
    new.close()
    os.remove(os.path.join(save_path, f"{save_name}.old"))
    input("导出完成，按回车键退出...")

if option == "3":
    suffix = input("需导入的文件后缀(默认：.pem)：")
    suffix_split = suffix.split(".")

    if suffix == "":
        suffix = ".pem"
    elif suffix_split[0] == "" and len(suffix_split) == 2:
        suffix = suffix
    elif suffix_split[-2] == "" and len(suffix_split) > 2:
        suffix = "." + suffix_split[-1]
    elif suffix_split[-2] != "" and len(suffix_split) >= 2:
        suffix = "." + suffix_split[-1]

    print(f"仅导入后缀为{suffix}的文件，请确保文件格式正确！")
    import_path = input("需导入的私钥路径:")
    if config["save_path"] == "cwd":
        save_path = os.getcwd()
    else:
        save_path = config["save_path"]
    save_file = os.path.join(save_path, f"{config['save_name']}.json")
    for file in os.listdir(import_path):
        if file.endswith(suffix):
            with open(os.path.join(import_path, file), "rb") as pem_bytes:
                pem_text = pem_bytes.read()
            f = fernet.Fernet(key)
            token = f.encrypt(pem_text)
            pem_json = {}
            if os.path.exists(save_file):
                with open(save_file, "r", encoding="utf-8") as f:
                    pem_json = json.load(f)
            pem_json[file.replace(suffix, "")] = token.decode()
            with open(save_file, "w+", encoding="utf-8") as pem_bytes:
                json.dump(pem_json, pem_bytes, ensure_ascii=True, indent=4)
        print(f"{file} - 导入完成")
    input("批量导入完成，按回车键退出...")

if option == "4":
    with open(read_path, "r", encoding="utf-8") as pem_bytes:
        token = json.load(pem_bytes)

    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

    print("私钥列表：")
    print("-------------------")
    for key,value in token.items():
        print("%s. %s" % (list(token.keys()).index(key) + 1, key))
    print("-------------------")
    input("按回车键退出...")