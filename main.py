import os
import sys
import json
import base64
import msvcrt
import platform
from cryptography import fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

version = "1.1.0"
print("----------------------------------------------")
print(f"Fernet key database for pem | Nya-WSL | v{version}")
print("----------------------------------------------")
option = input("1. 导入私钥\n2. 导出私钥\n3. 批量导入\n4. 查看私钥列表\n\n选项: ")
print("-------------------")

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
            msvcrt.putch('*'.encode(encoding='utf-8'))
    password = "".join(chars).encode()
    print("")
    if os.path.exists("salt"):
        with open("salt", "rb") as f:
            salt = f.read()
    else:
        # 生成盐
        salt = os.urandom(16)
        with open("salt", "wb") as f:
            f.write(salt)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = fernet.Fernet(key)

read_path = os.path.join(os.getcwd(), "pem.json")

if option == "1":
    import_path = input("需导入的私钥路径:")
    save_path = os.getcwd()
    save_name = input("密文别称:")
    file = os.path.join(save_path, "pem.json")
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
    input("导入完成，按任意键退出...")

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
        sys.exit("error password!")
    except:
        input("出现错误！")
        sys.exit("error password!")

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
    input("导出完成，按任意键退出...")

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

    print(f"批量导入仅支持导入后缀为{suffix}的文件，请确保文件格式正确！")
    import_path = input("需导入的私钥路径:")
    save_path = os.getcwd()
    save_file = os.path.join(save_path, "pem.json")
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
    input("批量导入完成，按任意键退出...")

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
    input("按任意键退出...")