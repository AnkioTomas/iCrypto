import sys
import json
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import argparse
from urllib.parse import parse_qs, urlencode, unquote, quote
# 常量
RequestFromClient = "0"
RequestToServer = "1"
ResponseFromServer = "2"
ResponseToClient = "3"
# 解析命令行参数
parser = argparse.ArgumentParser(description="处理加解密操作的脚本")
parser.add_argument("--operationType", required=True, help="操作类型: 0=RequestFromClient, 1=RequestToServer, 2=ResponseFromServer, 3=ResponseToClient")
parser.add_argument("--dataDir", required=True, help="数据文件的目录路径")
parser.add_argument("--initToken", required=True, help="初始Token")
parser.add_argument("--dynamicToken", required=True, help="动态Token")
args = parser.parse_args()
# 获取参数
operation = args.operationType
path = args.dataDir
initToken = args.initToken
dynamicToken = args.dynamicToken
# 生成 AES 密钥
def generate_aes_key(initToken, dynamicToken, sessionId):
    signTSFirst = initToken
    signTSecond = dynamicToken
    combined_string = signTSFirst + ";" + signTSecond
    md5_hash = hashlib.md5(combined_string.encode('utf-8')).hexdigest().upper()
    aeskey = md5_hash[8:24].encode('utf-8')
    return aeskey
aeskey = generate_aes_key(initToken, dynamicToken, sessionId)
# AES 加密函数
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size, style='pkcs7')
    encrypted_bytes = cipher.encrypt(padded_data)
    encrypted_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')
    return encrypted_base64
# AES 解密函数
def aes_decrypt(key, encrypted_text):
    encrypted_bytes = base64.b64decode(encrypted_text)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size, style='pkcs7')
    return decrypted_bytes.decode('utf-8')
# 读取文件内容
def get_request_body():
    with open(f'{path}/body.txt', 'r', encoding='utf-8') as file:
        return file.read()
def set_request_body(data):
    with open(f'{path}/body.txt', 'w', encoding='utf-8') as file:
        file.write(data)
def get_request_headers():
    with open(f'{path}/headers.txt', 'r', encoding='utf-8') as file:
        return file.read()
def set_request_headers(data):
    with open(f'{path}/headers.txt', 'w', encoding='utf-8') as file:
        file.write(data)
def get_response_body():
    with open(f'{path}/response_body.txt', 'r', encoding='utf-8') as file:
        return file.read()
def set_response_body(data):
    with open(f'{path}/response_body.txt', 'w', encoding='utf-8') as file:
        file.write(data)
# 根据操作类型执行相应的加解密操作
if operation == RequestFromClient:
    set_request_body(aes_decrypt(aeskey, get_request_body()))
elif operation == RequestToServer:
    body = get_request_body()
    set_request_body(aes_encrypt(aeskey, body))
elif operation == ResponseFromServer:
    body = json.loads(get_response_body())
    body['resp'] = json.loads(unquote(aes_decrypt(aeskey, body['resp'])))
    set_response_body(json.dumps(body))
elif operation == ResponseToClient:
    body = json.loads(get_response_body())
    body['resp'] = aes_encrypt(aeskey, quote(json.dumps(body['resp'])))
    set_response_body(json.dumps(body))
# 输出 success
print("success")
