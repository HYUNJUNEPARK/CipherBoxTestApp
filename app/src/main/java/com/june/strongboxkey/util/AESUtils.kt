package com.june.strongboxkey.util

import com.june.strongboxkey.constant.Constants.CIPHER_ALGORITHM
import javax.crypto.Cipher

class AESUtils {
    fun encryption(data: String, key: ByteArray): ByteArray {
        val data_bytes = data.toByteArray()
        val key = KeyProvider().byteArrayToKey(key)
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM) //AES/ECB/PKCS5Padding
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val result = cipher.doFinal(data_bytes)
        return result
    }

    fun decryption(data: ByteArray, key: ByteArray): String {
        val key = KeyProvider().byteArrayToKey(key)
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM) //AES/ECB/PKCS5Padding
        cipher.init(Cipher.DECRYPT_MODE, key)
        val result = cipher.doFinal(data)
        return String(result)
    }
}