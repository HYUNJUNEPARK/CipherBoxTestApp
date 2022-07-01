package com.june.strongboxkey.util

import android.util.Base64
import com.june.strongboxkey.Constants.CIPHER_ALGORITHM
import javax.crypto.Cipher

class Decryption {
//    private fun byteArrayDecryption(data: ByteArray, key: ByteArray): ByteArray {
//        val key = KeyProvider().byteArrayToKey(key)
//        val cipher = Cipher.getInstance(CIPHER_ALGORITHM) //AES/ECB/PKCS5Padding
//        cipher.init(Cipher.DECRYPT_MODE, key)
//        return cipher.doFinal(data)
//    }

//    fun decryption(data: String?, aesKey: String?): String {
//        val data_byets = Base64.decode(data, Base64.DEFAULT)
//        val key_bytes = Base64.decode(aesKey, Base64.DEFAULT)
//        val result = byteArrayDecryption(data_byets, key_bytes)
//        return String(result)
//    }


    fun decryption__(data: ByteArray, key: ByteArray): String {
        val key = KeyProvider().byteArrayToKey(key)
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM) //AES/ECB/PKCS5Padding
        cipher.init(Cipher.DECRYPT_MODE, key)

        val result = cipher.doFinal(data)
        return String(result)
    }
}