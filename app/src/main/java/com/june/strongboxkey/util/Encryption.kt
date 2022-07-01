package com.june.strongboxkey.util

import android.util.Base64
import com.june.strongboxkey.Constants.CIPHER_ALGORITHM
import javax.crypto.Cipher

class Encryption {
//    private fun byteArrayEncryption(data: ByteArray, key: ByteArray): ByteArray {
//        val key = KeyProvider().byteArrayToKey(key)
//        val cipher = Cipher.getInstance(CIPHER_ALGORITHM) //AES/ECB/PKCS5Padding
//        cipher.init(Cipher.ENCRYPT_MODE, key)
//        return cipher.doFinal(data)
//    }
//
//    fun encryption(data: String, key: String): String {
//        val data_bytes = data.toByteArray()
//        val key_bytes = Base64.decode(key, Base64.DEFAULT)
//        val result = byteArrayEncryption(data_bytes, key_bytes)
//        return Base64.encodeToString(result, Base64.DEFAULT)
//    }




    fun encryption__(data: String, key: ByteArray): ByteArray {
        val data_bytes = data.toByteArray()
        val key = KeyProvider().byteArrayToKey(key)
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM) //AES/ECB/PKCS5Padding
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val result = cipher.doFinal(data_bytes)
        //val result_str = Base64.encodeToString(result, Base64.DEFAULT)
        return result
    }

}