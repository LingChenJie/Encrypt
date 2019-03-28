package com.jc.encrypt.rsa

import java.security.PrivateKey
import java.security.PublicKey

/**
 * RSA扩展工具类，添加分段加密
 */
object RSAUtilsExt {

    // RSA 算法规定：待加密的字节数不能超过密钥的长度值除以 8 再减去 11（即：KeySize / 8 - 11）
    // 而加密后得到密文的字节数，正好是密钥的长度值除以 8（即：KeySize / 8）。
    private const val SUPPORT_BUFFER_SIZE = (RSAUtils.DEFAULT_KEY_SIZE / 8) - 11// 当前秘钥支持加密的最大字节数
    private val DEFAULT_SPLIT = "#SPLIT#".toByteArray() // 分段加密的分隔符

    /**
     * 使用公钥分段加密
     */
    fun encrypt(data: ByteArray, publicKey: PublicKey): ByteArray {
        val dataSize = data.size
        if (dataSize <= SUPPORT_BUFFER_SIZE) {
            return RSAUtils.encrypt(data, publicKey)
        }
        val allBytes = ArrayList<Byte>(2048)
        var bufIndex = 0
        var subDataLoop = 0
        var buf = ByteArray(SUPPORT_BUFFER_SIZE)

        for (i in 0 until dataSize) {
            buf[bufIndex] = data[i]
            if (++bufIndex == SUPPORT_BUFFER_SIZE || i == dataSize - 1) {
                subDataLoop++
                if (subDataLoop != 1) {
                    for (b in DEFAULT_SPLIT) {
                        allBytes.add(b)
                    }
                }
                val encryptBytes = RSAUtils.encrypt(buf, publicKey)
                for (b in encryptBytes) {
                    allBytes.add(b)
                }
                bufIndex = 0
                if (i == dataSize - 1) {
                    buf = ByteArray(0)
                } else {
                    buf = ByteArray(Math.min(SUPPORT_BUFFER_SIZE, dataSize - i - 1))
                }
            }
        }

        val result = ByteArray(allBytes.size)
        for (i in 0 until result.size) {
            result[i] = allBytes[i]
        }
        return result

    }

    /**
     * 使用私钥分段加密
     */
    fun encrypt(data: ByteArray, privateKey: PrivateKey): ByteArray {
        val dataSize = data.size
        if (dataSize <= SUPPORT_BUFFER_SIZE) {
            return RSAUtils.encrypt(data, privateKey)
        }
        val allBytes = ArrayList<Byte>(2048)
        var bufIndex = 0
        var subDataLoop = 0
        var buf = ByteArray(SUPPORT_BUFFER_SIZE)

        for (i in 0 until dataSize) {
            buf[bufIndex] = data[i]
            if (++bufIndex == SUPPORT_BUFFER_SIZE || i == dataSize - 1) {
                subDataLoop++
                if (subDataLoop != 1) {
                    for (b in DEFAULT_SPLIT) {
                        allBytes.add(b)
                    }
                }
                val encryptBytes = RSAUtils.encrypt(buf, privateKey)
                for (b in encryptBytes) {
                    allBytes.add(b)
                }
                bufIndex = 0
                if (i == dataSize - 1) {
                    buf = ByteArray(0)
                } else {
                    buf = ByteArray(Math.min(SUPPORT_BUFFER_SIZE, dataSize - i - 1))
                }
            }
        }

        val result = ByteArray(allBytes.size)
        for (i in 0 until result.size) {
            result[i] = allBytes[i]
        }
        return result

    }

    /**
     * 使用公钥分段解密
     */
    fun decrypt(data: ByteArray, publicKey: PublicKey): ByteArray {
        val splitLen = DEFAULT_SPLIT.size
        val dataSize = data.size
        val allBytes = ArrayList<Byte>(1024)
        var lastStartIndex = 0
        var index = 0// 代替i
        for (i in 0 until dataSize) {
            if (index >= dataSize) {
                break
            }

            val byte = data[index]
            var isMatchSplit = false
            if (index == dataSize - 1) {// 最后一个字节
                val part = ByteArray(dataSize - lastStartIndex)
                System.arraycopy(data, lastStartIndex, part, 0, part.size)
                val decryptPart = RSAUtils.decrypt(part, publicKey)
                decryptPart.forEach { allBytes.add(it) }
            } else if (byte == DEFAULT_SPLIT[0]) {// 这个是以split[0]开头
                if (index + splitLen < dataSize) {
                    for (j in 0 until splitLen) {
                        if (DEFAULT_SPLIT[j] != data[index + j]) {
                            break
                        }
                        if (j == splitLen - 1) {
                            // 验证到split的最后一位，都没有break，则表明已经确认是split段
                            isMatchSplit = true
                        }
                    }
                }
            }

            if (isMatchSplit) {
                val part = ByteArray(index - lastStartIndex)
                System.arraycopy(data, lastStartIndex, part, 0, part.size)
                val decryptPart = RSAUtils.decrypt(part, publicKey)
                decryptPart.forEach { allBytes.add(it) }
                lastStartIndex = index + splitLen
                index = lastStartIndex - 1
            }

            index++
        }

        val result = ByteArray(allBytes.size)
        for (i in 0 until result.size) {
            result[i] = allBytes[i]
        }
        return result
    }

    /**
     * 使用私钥分段解密
     */
    fun decrypt(data: ByteArray, privateKey: PrivateKey): ByteArray {
        val splitLen = DEFAULT_SPLIT.size
        val dataSize = data.size
        val allBytes = ArrayList<Byte>(1024)
        var lastStartIndex = 0
        var index = 0// 代替i
        for (i in 0 until dataSize) {
            if (index >= dataSize) {
                break
            }

            val byte = data[index]
            var isMatchSplit = false
            if (index == dataSize - 1) {// 最后一个字节
                val part = ByteArray(dataSize - lastStartIndex)
                System.arraycopy(data, lastStartIndex, part, 0, part.size)
                val decryptPart = RSAUtils.decrypt(part, privateKey)
                decryptPart.forEach { allBytes.add(it) }
            } else if (byte == DEFAULT_SPLIT[0]) {// 这个是以split[0]开头
                if (index + splitLen < dataSize) {
                    for (j in 0 until splitLen) {
                        if (DEFAULT_SPLIT[j] != data[index + j]) {
                            break
                        }
                        if (j == splitLen - 1) {
                            // 验证到split的最后一位，都没有break，则表明已经确认是split段
                            isMatchSplit = true
                        }
                    }
                }
            }

            if (isMatchSplit) {
                val part = ByteArray(index - lastStartIndex)
                System.arraycopy(data, lastStartIndex, part, 0, part.size)
                val decryptPart = RSAUtils.decrypt(part, privateKey)
                decryptPart.forEach { allBytes.add(it) }
                lastStartIndex = index + splitLen
                index = lastStartIndex - 1
            }

            index++
        }

        val result = ByteArray(allBytes.size)
        for (i in 0 until result.size) {
            result[i] = allBytes[i]
        }
        return result
    }
}