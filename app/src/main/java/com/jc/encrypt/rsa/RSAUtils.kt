package com.jc.encrypt.rsa

import java.math.BigInteger
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

/**
 * RSA工具类
 */
object RSAUtils {

    private const val RSA = "RSA"// 密钥算法
    private const val ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding" // 加密填充方式
    const val DEFAULT_KEY_SIZE = 1024 // 秘钥默认长度
    const val SIGN_ALGORITHMS = "SHA1WithRSA" // 签名算法


    /**
     * 生成RSA密钥对
     * keyLength: 密钥长度,范围：512～2048,一般1024
     */
    @JvmStatic
    fun generateRSAKeyPair(keyLength: Int): KeyPair {
        val generator = KeyPairGenerator.getInstance(RSA)
        generator.initialize(keyLength)
        return generator.genKeyPair()
    }

    /**
     * 获取公钥
     */
    @JvmStatic
    fun getPublicKey(decode: ByteArray): PublicKey {
        val keySpec = X509EncodedKeySpec(decode)
        val keyFactory = KeyFactory.getInstance(RSA)
        return keyFactory.generatePublic(keySpec)
    }

    /**
     * 获取公钥
     */
    @JvmStatic
    fun getPublicKey(modulesStr: String, exponentStr: String): PublicKey {
        val modules = BigInteger(modulesStr)
        val exponent = BigInteger(exponentStr)
        val publickeySpec = RSAPublicKeySpec(modules, exponent)
        val factory = KeyFactory.getInstance(RSA)
        return factory.generatePublic(publickeySpec)
    }

    /**
     * 获取私钥
     */
    @JvmStatic
    fun getPrivate(decode: ByteArray): PrivateKey {
        val keySpec = PKCS8EncodedKeySpec(decode)
        val keyFactory = KeyFactory.getInstance(RSA)
        return keyFactory.generatePrivate(keySpec)
    }

    /**
     * 获取私钥
     */
    @JvmStatic
    fun getPrivateKey(modulesStr: String, exponentStr: String): PrivateKey {
        val modules = BigInteger(modulesStr)
        val exponent = BigInteger(exponentStr)
        val privatekeySpec = RSAPrivateKeySpec(modules, exponent)
        val factory = KeyFactory.getInstance(RSA)
        return factory.generatePrivate(privatekeySpec)
    }

    /**
     * 使用公钥加密
     */
    @JvmStatic
    fun encrypt(data: ByteArray, publicKey: PublicKey): ByteArray {
        val cipher = Cipher.getInstance(ECB_PKCS1_PADDING)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return cipher.doFinal(data)
    }


    /**
     * 使用私钥加密
     */
    @JvmStatic
    fun encrypt(data: ByteArray, privateKey: PrivateKey): ByteArray {
        val cipher = Cipher.getInstance(ECB_PKCS1_PADDING)
        cipher.init(Cipher.ENCRYPT_MODE, privateKey)
        return cipher.doFinal(data)
    }

    /**
     * 使用公钥解密
     */
    @JvmStatic
    fun decrypt(data: ByteArray, publicKey: PublicKey): ByteArray {
        val cipher = Cipher.getInstance(ECB_PKCS1_PADDING)
        cipher.init(Cipher.DECRYPT_MODE, publicKey)
        return cipher.doFinal(data)
    }

    /**
     * 使用私钥解密
     */
    @JvmStatic
    fun decrypt(data: ByteArray, privateKey: PrivateKey): ByteArray {
        val cipher = Cipher.getInstance(ECB_PKCS1_PADDING)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return cipher.doFinal(data)
    }


    /**
     * 签名
     */
    @JvmStatic
    fun sign(data: ByteArray, privateKey: PrivateKey): ByteArray {
        val signature = Signature.getInstance(SIGN_ALGORITHMS)
        signature.initSign(privateKey)
        signature.update(data)
        return signature.sign()
    }

    /**
     * 检查签名
     * data: 原数据
     * sign：签名后结果
     * publicKey：公钥
     */
    @JvmStatic
    fun verify(data: ByteArray, sign: ByteArray, publicKey: PublicKey): Boolean {
        val signature = Signature.getInstance(SIGN_ALGORITHMS)
        signature.initVerify(publicKey)
        signature.update(data)
        return signature.verify(sign)
    }
}
