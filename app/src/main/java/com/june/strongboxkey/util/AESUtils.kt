package com.june.strongboxkey.util

import android.util.Base64
import com.june.strongboxkey.constant.Constants.CIPHER_ALGORITHM
import java.security.Key
import javax.crypto.Cipher

class AESUtils {
    fun encryption(data: String, key: ByteArray): String {
        val data: ByteArray = data.toByteArray()
        val key: Key = KeyProvider().byteArrayToKey(key)
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM) //AES/ECB/PKCS5Padding
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val _result: ByteArray = cipher.doFinal(data)
        val result: String = Base64.encodeToString(_result, Base64.DEFAULT)
        return result
    }

    fun decryption(data: String, key: ByteArray): String {
        val key: Key = KeyProvider().byteArrayToKey(key)
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM) //AES/ECB/PKCS5Padding
        cipher.init(Cipher.DECRYPT_MODE, key)
        val data: ByteArray = Base64.decode(data, Base64.DEFAULT)
        val result: ByteArray = cipher.doFinal(data)
        return String(result)
    }
}