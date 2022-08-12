package com.june.strongboxkey.strongbox

import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.Key
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AESCipher {
    private val iv: ByteArray = ByteArray(16)

    //TODO hash -> keyId: String
    fun encrypt(message: String, hash: ByteArray): String {
        val userMessage: ByteArray = message.toByteArray()
        //hash -> key
        val key: Key = SecretKeySpec(
            hash,
            KeyProperties.KEY_ALGORITHM_AES
        )
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            key,
            IvParameterSpec(iv)
        )
        val result: String
        cipher.doFinal(userMessage).let { encryptedMessage ->
            result = Base64.encodeToString(encryptedMessage, Base64.DEFAULT)
        }
        return result
    }

    fun decrypt(message: String, hash: ByteArray): String {
        //hash -> key
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
        val result: ByteArray
        Base64.decode(message, Base64.DEFAULT).let { decryptedMessage ->
            result = cipher.doFinal(decryptedMessage)
        }
        return String(result)
    }

    //ECB
    fun encryptMessageECB(userInput: String, hash: ByteArray): String {
        val input: ByteArray = userInput.toByteArray()
        val key: Key = SecretKeySpec(
            hash,
            KeyProperties.KEY_ALGORITHM_AES
        )
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            key
        )
        val result: String
        cipher.doFinal(input).let { bytes ->
            result = Base64.encodeToString(bytes, Base64.DEFAULT)
        }
        return result
    }

    fun decryptMessageECB(encryptedData: String, hash: ByteArray): String {
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