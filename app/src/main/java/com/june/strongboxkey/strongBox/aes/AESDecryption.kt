package com.june.strongboxkey.strongBox.aes

import android.security.keystore.KeyProperties
import android.util.Base64
import com.june.strongboxkey.strongBox.StrongBoxConstants.iv
import java.security.Key
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AESDecryption {
    fun decryptionCBCMode(encryptedData: String, hash: ByteArray): String {
        val key: Key = SecretKeySpec(
            hash,
            KeyProperties.KEY_ALGORITHM_AES
        )

        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
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

        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            key
        )
        val decryptedData: ByteArray = Base64.decode(encryptedData, Base64.DEFAULT)
        val result: ByteArray = cipher.doFinal(decryptedData)
        return String(result)
    }
}