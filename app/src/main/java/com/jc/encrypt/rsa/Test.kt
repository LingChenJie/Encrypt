package com.jc.encrypt.rsa

fun main() {

    generateKeyPair()// 生成密钥对
    encrypt()// 加密解密
    checkSign()// 签名验签
}


const val path = "/Users/xiaosu/test"

/**
 * 随机生成密钥对
 */
fun generateKeyPair() {
    RSAHelper.genKeyPair(path)
}

/**
 * 公钥加密，私钥解密
 * 私钥加密，公钥解密
 */
fun encrypt() {
    val data = "我爱中国我爱中国我爱中国我爱中国我爱中国我爱中国我爱中国我爱中国abcd01234567890123456".toByteArray()

    // 获取公私钥
    val publicKeyBase64Str = RSAHelper.readPublicKeyFile(path)
    val privateKeyBase64Str = RSAHelper.readPrivateKeyFile(path)
    val publicKey = RSAHelper.getPublicKey(publicKeyBase64Str!!)
    val privateKey = RSAHelper.getPrivateKey(privateKeyBase64Str!!)

    // 公钥加密，私钥解密
    val encryptData = RSAUtilsExt.encrypt(data, publicKey)
    val decryptData = RSAUtilsExt.decrypt(encryptData, privateKey)
    println(String(decryptData))

    // 私钥加密，公钥解密
    val encrypt = RSAUtilsExt.encrypt(data, RSAHelper.getPrivateKey(privateKeyBase64Str!!))
    val decrypt = RSAUtilsExt.decrypt(encrypt, RSAHelper.getPublicKey(publicKeyBase64Str!!))
    val decryStr = String(decrypt)
    println(decryStr)
}

/**
 * 校验签名
 */
fun checkSign() {
    // 获取公私钥
    val publicKeyBase64Str = RSAHelper.readPublicKeyFile(path)
    val privateKeyBase64Str = RSAHelper.readPrivateKeyFile(path)
    val publicKey = RSAHelper.getPublicKey(publicKeyBase64Str!!)
    val privateKey = RSAHelper.getPrivateKey(privateKeyBase64Str!!)

    val data =
        "我爱中国我爱中国我爱中国我爱中国我爱中国我爱中国我爱中国我爱中国abcd01234567890123456我爱中国我爱中国我爱中国我爱中国我爱中国我爱中国我爱中国我爱中国abcd01234567890123456".toByteArray()

    // 私钥签名，公钥校验签名
    val signData = RSAUtils.sign(data, privateKey)
    val verify = RSAUtils.verify(data, signData, publicKey)
    println("verify:$verify")
}


