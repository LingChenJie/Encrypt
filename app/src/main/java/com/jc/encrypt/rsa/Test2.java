package com.jc.encrypt.rsa;

import java.security.PrivateKey;
import java.security.PublicKey;

public class Test2 {

    private static final String PATH = "/Users/xiaosu/test";

    public static void main(String[] args) {
        generateKeyPair(); // 生成密钥对
        encrypt();// 加密解密
    }

    private static void generateKeyPair() {
        RSAHelper.genKeyPair(PATH);
    }

    private static void encrypt() {
        byte[] data = "我爱中国我爱中国我爱中国我爱中国我爱中国我爱中国我爱中国我爱中国abcd01234567890123456".getBytes();

        // 获取公私钥
        String publicKeyBase64Str = RSAHelper.readPublicKeyFile(PATH);
        String privateKeyBase64Str = RSAHelper.readPrivateKeyFile(PATH);
        PublicKey publicKey = RSAHelper.getPublicKey(publicKeyBase64Str);
        PrivateKey privateKey = RSAHelper.getPrivateKey(privateKeyBase64Str);

        // 公钥加密，私钥解密
        byte[] encryptData = RSAUtilsExt.encrypt(data, publicKey);
        byte[] decryptData = RSAUtilsExt.decrypt(encryptData, privateKey);
        System.out.println(new String(decryptData));

        // 私钥加密，公钥解密
        byte[] encrypt = RSAUtilsExt.encrypt(data, RSAHelper.getPrivateKey(privateKeyBase64Str));
        byte[] decrypt = RSAUtilsExt.decrypt(encrypt, RSAHelper.getPublicKey(publicKeyBase64Str));
        String decryStr = new String(decrypt);
        System.out.println(decryStr);
    }

}
