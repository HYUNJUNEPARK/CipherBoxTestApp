package com.june.strongboxkey.strongBox.aes

import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.widget.Toast
import com.june.strongboxkey.strongBox.StrongBoxConstants
import com.june.strongboxkey.strongBox.StrongBoxConstants.CIPHER_AES_CBC_PADDING
import com.june.strongboxkey.strongBox.StrongBoxConstants.CIPHER_AES_ECB_PADDING
import com.june.strongboxkey.strongBox.StrongBoxConstants.iv
import com.june.strongboxkey.strongBox.aes.AESEncryption.Companion.keyStore
import java.security.Key
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AESDecryption {
    //TEST
//    private val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
//        load(null)
//    }

    //https://oozou.com/blog/an-easy-way-to-secure-your-sensitive-data-on-android-92

    //TEST


    fun decryptionCBCMode(encryptedData: String, hash: ByteArray): String {
        val key: Key = SecretKeySpec(
            hash,
            KeyProperties.KEY_ALGORITHM_AES
        )


        val passwordKS = "wshr.ut".toCharArray()

        val sk = keyStore.getKey("aaaaa", passwordKS)

        if (keyStore.containsAlias("aaaaa")) {
            Log.d("testLog", "decryptionCBCMode: success")
        }
        else {
            Log.d("testLog", "decryptionCBCMode: failed")
        }


        val cipher = Cipher.getInstance(CIPHER_AES_CBC_PADDING) //AES/CBC/PKCS7Padding
        cipher.init(
            Cipher.DECRYPT_MODE,
            key,
            IvParameterSpec(iv)
        )
        val decryptedData: ByteArray = Base64.decode(encryptedData, Base64.DEFAULT)
        val result: ByteArray = cipher.doFinal(decryptedData)
        return String(result)
    }

    fun decryptionECBMode(encryptedData: String, hash: ByteArray): String {
        val key: Key = SecretKeySpec(
            hash,
            KeyProperties.KEY_ALGORITHM_AES
        )

        val cipher = Cipher.getInstance(CIPHER_AES_ECB_PADDING) //AES/ECB/PKCS5Padding
        cipher.init(
            Cipher.DECRYPT_MODE,
            key
        )
        val decryptedData: ByteArray = Base64.decode(encryptedData, Base64.DEFAULT)
        val result: ByteArray = cipher.doFinal(decryptedData)
        return String(result)
    }
}