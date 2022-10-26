package com.study.cipherbox.strongbox

import android.security.keystore.KeyProperties
import android.util.Base64
import com.study.cipherbox.strongbox.KeyProvider.Companion.ENCRYPTION_PADDING_PKCS7
import java.security.Key
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AESUtils {
    companion object {
        var iv: ByteArray? = null
    }

    fun encrypt(message: String, key: ByteArray): String {
        val sharedSecretKey: Key = SecretKeySpec(key, KeyProperties.KEY_ALGORITHM_AES)
        val userInputData: ByteArray = message.toByteArray()
        val cipher = Cipher.getInstance(ENCRYPTION_PADDING_PKCS7) //AES/CBC/PKCS7Padding
        cipher.init(
            Cipher.ENCRYPT_MODE,
            sharedSecretKey
        )
        iv = cipher.iv
        val _result: ByteArray = cipher.doFinal(userInputData)
        val result: String = Base64.encodeToString(_result, Base64.DEFAULT)
        return result
    }

    fun decrypt(message: String, key: ByteArray): String {
        val sharedSecretKey: Key = SecretKeySpec(key, KeyProperties.KEY_ALGORITHM_AES)
        val cipher = Cipher.getInstance(ENCRYPTION_PADDING_PKCS7) //AES/CBC/PKCS7Padding
        cipher.init(
            Cipher.DECRYPT_MODE,
            sharedSecretKey,
            IvParameterSpec(iv)
        )
        val decryptedData: ByteArray = Base64.decode(message, Base64.DEFAULT)
        val result: ByteArray = cipher.doFinal(decryptedData)
        return String(result)
    }
}