package com.jc.encrypt.rsa

import com.jc.encrypt.base64.Base64
import java.io.*
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

/**
 * RSA帮助类
 */
object RSAHelper {

    /**
     * 随机生成密钥对，并base64编码保存在指定路径下
     */
    fun genKeyPair(path: String) {
        val keyPair = RSAUtils.generateRSAKeyPair(RSAUtils.DEFAULT_KEY_SIZE)
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey
        // 公私钥base64编码
        val publicKeyStr = Base64.encode(publicKey.encoded)
        val privateKeyStr = Base64.encode(privateKey.encoded)
        // 写入到文件中
        val pubfw = FileWriter(path + File.separator + "publicKey.keystore")
        val prifw = FileWriter(path + File.separator + "privateKey.keystore")
        val pubbw = BufferedWriter(pubfw)
        val pribw = BufferedWriter(prifw)
        pubbw.write(publicKeyStr)
        pribw.write(privateKeyStr)
        pubbw.flush()
        pubbw.close()
        pribw.flush()
        pribw.close()

        val stringBuffer = StringBuffer()
        stringBuffer.append("publicKey exponent:${publicKey.publicExponent}\n")
        stringBuffer.append("publicKey modules:${publicKey.modulus}\n")
        stringBuffer.append("publicKey format:${publicKey.format}\n")
        stringBuffer.append("---------------------华丽的分割线-------------------------\n")
        stringBuffer.append("privateKey exponent:${privateKey.privateExponent}\n")
        stringBuffer.append("privateKey modules:${privateKey.modulus}\n")
        stringBuffer.append("privateKey format:${privateKey.format}\n")
        val modulusfw = FileWriter(path + File.separator + "modulus.txt")
        val modulusbw = BufferedWriter(modulusfw)
        modulusbw.write(stringBuffer.toString())
        modulusbw.flush()
        modulusbw.close()
    }

    /**
     * 读取指定目录下的公钥文件内容
     */
    fun readPublicKeyFile(path: String): String? {
        try {
            val reader = BufferedReader(FileReader(path + File.separator + "publicKey.keystore"))
            val builder = StringBuilder()
            var line: String?

            line = reader.readLine()
            while (line != null) {
                builder.append(line)
                line = reader.readLine()
            }
            reader.close()
            return builder.toString()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    /**
     * 读取指定目录下的私钥文件内容
     */
    fun readPrivateKeyFile(path: String): String? {
        try {
            val reader = BufferedReader(FileReader(path + File.separator + "privateKey.keystore"))
            val builder = StringBuilder()
            var line: String?

            line = reader.readLine()
            while (line != null) {
                builder.append(line)
                line = reader.readLine()
            }
            reader.close()
            return builder.toString()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    /**
     * 从base64编码后的字符串中获取公钥
     */
    fun getPublicKey(publicKeyBase64Str: String): PublicKey {
        val decode = Base64.decode(publicKeyBase64Str)
        return RSAUtils.getPublicKey(decode)
    }

    /**
     * 从base64编码后的字符串中获取私钥
     */
    fun getPrivateKey(privateKeyBase64Str: String): PrivateKey {
        val decode = Base64.decode(privateKeyBase64Str)
        return RSAUtils.getPrivate(decode)
    }


}