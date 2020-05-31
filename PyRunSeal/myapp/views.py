from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
# from django.utils.six import BytesIO
import requests
import json
import time
import os
import psutil
# import face_recognition
import hashlib
import base64
# 引入Seal包
#from . import paillier


# Create your views here.

def test(request):
    if request.method == "GET":
        a = request.GET.get("a")
        b = request.GET.get("b")
        c = a + b
    return JsonResponse({
        "status_code": 0,
        "data": c
    })

from seal import *
from seal_help import *
import binascii
def BFV_kengen(request):
# 返回公钥public_key，relin_keys，密钥secret_key和context。
# 其中算法的任何操作都要用到这个context。一组钥匙对应一个context。计算时需要用到relin_keys
# 可以把context和relin_keys也理解为公钥
    keygen = KeyGenerator(BFV_context)
    keygen.public_key().save("pub")
    keygen.secret_key().save("sec")
    keygen.relin_keys().save("rel")
    pub = open("pub","rb")
    sec = open("sec","rb")
    rel = open("rel","rb")
    public_key =''.join(['%02X' %x  for x in pub.read()])
    secret_key =''.join(['%02X' %x  for x in sec.read()])
    relin_keys =''.join(['%02X' %x  for x in rel.read()])
    pub.close()
    sec.close()
    rel.close()
    return JsonResponse({
        "public_key": public_key,
        "relin_keys": relin_keys,
        "secret_key": secret_key
    })

def  BFV_Encrypt(request):  # x是要加密的明文,应该是int型整数，public_key是公钥，返回x对应的密文类
    if request.method == "POST":
        x = request.POST.get("x")
        pub = open("pub","wb")
        public_key = request.POST.get("public_key")
        pub.write(bytes.fromhex(public_key))
        public_key = KeyGenerator(BFV_context).public_key()
        public_key.load(BFV_context,"pub")
        pub.close()
    x = str(x)
    encryptor = Encryptor(BFV_context, public_key)
    x_encrypted = Ciphertext()
    x_plain = Plaintext(x)
    encryptor.encrypt(x_plain, x_encrypted)
    x_encrypted.save("cipher")
    cipher = open("cipher","rb")
    cipher_str=''.join(['%02X' %x  for x in cipher.read()])
    cipher.close()
    return JsonResponse({
        "x_encrypted": cipher_str
    })


def BFV_Decrypt(request):  # x_encrypted是明文x对应的密文类，secret_key是密钥，返回x_encrypted对应的明文
    if request.method == "POST":
        cip = open("cip","wb")
        cip.write(bytes.fromhex(request.POST.get("x_encrypted")))
        x_encrypted = Ciphertext()
        x_encrypted.load(BFV_context,"cip")
        cip.close()
        sec = open("sec","wb")
        sec.write(bytes.fromhex(request.POST.get("secret_key")))
        secret_key = KeyGenerator(BFV_context).secret_key()
        secret_key.load(BFV_context,"sec")
    decryptor = Decryptor(BFV_context, secret_key)
    x_decrypted = Plaintext()
    decryptor.decrypt(x_encrypted, x_decrypted)
    return JsonResponse({
        "x_decrypted": x_decrypted.to_string()
    })


def BFV_add(request):  # x_encrypted,y_encrypted是明文x，y对应的密文类，返回x+y对应的密文类
    if request.method == "POST":
        cip = open("cip","wb")
        cip.write(bytes.fromhex(request.POST.get("x_encrypted")))
        x_encrypted = Ciphertext()
        x_encrypted.load(BFV_context,"cip")
        cip = open("cip","wb")
        cip.write(bytes.fromhex(request.POST.get("y_encrypted")))
        y_encrypted = Ciphertext()
        y_encrypted.load(BFV_context,"cip")
        rel = open("rel","wb")
        rel.write(bytes.fromhex(request.POST.get("relin_keys")))
        relin_keys = KeyGenerator(BFV_context).relin_keys()
        relin_keys.load(BFV_context,"rel")        
    evaluator = Evaluator(BFV_context)
    add_encrypted = Ciphertext()
    plain_zero = Plaintext("0")
    evaluator.add_plain(x_encrypted, plain_zero, add_encrypted)
    evaluator.add_inplace(add_encrypted, y_encrypted)
    evaluator.relinearize_inplace(add_encrypted, relin_keys)
    add_encrypted.save("cipher")
    cipher = open("cipher","rb")
    add_encrypted=''.join(['%02X' %x  for x in cipher.read()])
    cipher.close()
    return JsonResponse({
        "add_encrypted": add_encrypted
    })

def BFV_mul(request):  # x_encrypted,y_encrypted是明文x，y对应的密文类，返回x*y对应的密文类
    if request.method == "POST":
        cip = open("cip","wb")
        cip.write(bytes.fromhex(request.POST.get("x_encrypted")))
        x_encrypted = Ciphertext()
        x_encrypted.load(BFV_context,"cip")
        cip = open("cip","wb")
        cip.write(bytes.fromhex(request.POST.get("y_encrypted")))
        y_encrypted = Ciphertext()
        y_encrypted.load(BFV_context,"cip")
        rel = open("rel","wb")
        rel.write(bytes.fromhex(request.POST.get("relin_keys")))
        relin_keys = KeyGenerator(BFV_context).relin_keys()
        relin_keys.load(BFV_context,"rel")    
    evaluator = Evaluator(BFV_context)
    mul_encrypted = Ciphertext()
    plain_zero = Plaintext("0")
    evaluator.add_plain(x_encrypted, plain_zero, mul_encrypted)
    evaluator.multiply_inplace(mul_encrypted, y_encrypted)
    evaluator.relinearize_inplace(mul_encrypted, relin_keys)
    mul_encrypted.save("cipher")
    cipher = open("cipher","rb")
    mul_encrypted=''.join(['%02X' %x  for x in cipher.read()])
    cipher.close()
    return JsonResponse({
        "mul_encrypted": mul_encrypted
    })



def CKKS_kengen(request):
# 返回公钥public_key，relin_keys，密钥secret_key和context。
# 其中BFV算法的任何操作都要用到这个context。一组钥匙对应一个context。计算时需要用到rc_key().save("pub")
    keygen = KeyGenerator(CKKS_context)
    keygen.public_key().save("pub")
    keygen.secret_key().save("sec")
    keygen.relin_keys().save("rel")
    pub = open("pub","rb")
    sec = open("sec","rb")
    rel = open("rel","rb")
    public_key =''.join(['%02X' %x  for x in pub.read()])
    secret_key =''.join(['%02X' %x  for x in sec.read()])
    relin_keys =''.join(['%02X' %x  for x in rel.read()])
    pub.close()
    sec.close()
    rel.close()
    return JsonResponse({
        "public_key": public_key,
        "relin_keys": relin_keys,
        "secret_key": secret_key
    })


def CKKS_Encrypt(request):  # x是要加密的明文，public_key是公钥，返回x对应的密文类
    if request.method == "POST":
        x = request.POST.get("x")
        pub = open("pub","wb")
        public_key = request.POST.get("public_key")
        pub.write(bytes.fromhex(public_key))
        public_key = KeyGenerator(CKKS_context).public_key()
        public_key.load(CKKS_context,"pub")
        pub.close()
    encryptor = Encryptor(CKKS_context, public_key)
    encoder = CKKSEncoder(CKKS_context)
    inputs = DoubleVector([x])
    plain = Plaintext()
    scale = pow(2.0, 30)
    encoder.encode(inputs, scale, plain)
    encrypted = Ciphertext()
    encryptor.encrypt(plain, encrypted)
    encrypted.save("cipher")
    cipher = open("cipher","rb")
    cipher_str=''.join(['%02X' %x  for x in cipher.read()])
    cipher.close()
    return JsonResponse({
        "x_encrypted": cipher_str
    })

def CKKS_Decrypt(request):  # x_encrypted是明文x对应的密文类，secret_key是密钥，返回x_encrypted对应的明文
    if request.method == "POST":
        cip = open("cip","wb")
        cip.write(bytes.fromhex(request.POST.get("x_encrypted")))
        x_encrypted = Ciphertext()
        x_encrypted.load(BFV_context,"cip")
        cip.close()
        sec = open("sec","wb")
        sec.write(bytes.fromhex(request.POST.get("secret_key")))
        secret_key = KeyGenerator(BFV_context).secret_key()
        secret_key.load(CKKS_context,"sec")    
    decryptor = Decryptor(CKKS_context, secret_key)
    encoder = CKKSEncoder(CKKS_context)
    x_decrypted = Plaintext()
    output = DoubleVector()
    decryptor.decrypt(x_encrypted, x_decrypted)
    encoder.decode(x_decrypted, output)
    return JsonResponse({
        "x_decrypted": output[0]
    })  


def CKKS_add(request):  # x_encrypted,y_encrypted是明文x，y对应的密文类，返回x+y对应的密文类
    if request.method == "POST":
        cip = open("cip","wb")
        cip.write(bytes.fromhex(request.POST.get("x_encrypted")))
        x_encrypted = Ciphertext()
        x_encrypted.load(CKKS_context,"cip")
        cip = open("cip","wb")
        cip.write(bytes.fromhex(request.POST.get("y_encrypted")))
        y_encrypted = Ciphertext()
        y_encrypted.load(CKKS_context,"cip")
        rel = open("rel","wb")
        rel.write(bytes.fromhex(request.POST.get("relin_keys")))
        relin_keys = KeyGenerator(CKKS_context).relin_keys()
        relin_keys.load(CKKS_context,"rel")
    evaluator = Evaluator(CKKS_context)
    add_encrypted = Ciphertext()
    evaluator.add(x_encrypted, y_encrypted, add_encrypted)
    evaluator.relinearize_inplace(add_encrypted, relin_keys)
    add_encrypted.save("cipher")
    cipher = open("cipher","rb")
    add_encrypted=''.join(['%02X' %x  for x in cipher.read()])
    cipher.close()
    return JsonResponse({
        "add_encrypted": add_encrypted
    })    


def CKKS_mul(request):  # x_encrypted,y_encrypted是明文x，y对应的密文类，返回x*y对应的密文类
    if request.method == "POST":
        cip = open("cip","wb")
        cip.write(bytes.fromhex(request.POST.get("x_encrypted")))
        x_encrypted = Ciphertext()
        x_encrypted.load(CKKS_context,"cip")
        cip = open("cip","wb")
        cip.write(bytes.fromhex(request.POST.get("y_encrypted")))
        y_encrypted = Ciphertext()
        y_encrypted.load(CKKS_context,"cip")
        rel = open("rel","wb")
        rel.write(bytes.fromhex(request.POST.get("relin_keys")))
        relin_keys = KeyGenerator(BFV_context).relin_keys()
        relin_keys.load(CKKS_context,"rel")
    evaluator = Evaluator(CKKS_context)
    mul_encrypted = Ciphertext()
    evaluator.multiply(x_encrypted, y_encrypted, mul_encrypted)
    evaluator.relinearize_inplace(mul_encrypted, relin_keys)
    mul_encrypted.save("cipher")
    cipher = open("cipher","rb")
    mul_encrypted=''.join(['%02X' %x  for x in cipher.read()])
    cipher.close()
    return JsonResponse({
        "mul_encrypted": mul_encrypted
    })



