package com.june.strongboxkey.strongBox

import android.security.keystore.KeyProperties
import android.util.Base64
import com.june.strongboxkey.strongBox.StrongBoxConstants.CIPHER_AES_CBC_PADDING
import com.june.strongboxkey.strongBox.StrongBoxConstants.CIPHER_AES_ECB_PADDING
import com.june.strongboxkey.strongBox.StrongBoxConstants.iv
import java.security.Key
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AESUtil {
//[START ECB Mode]
    fun encryptionECBMode(userInput: String, hash: ByteArray): String {
        val input: ByteArray = userInput.toByteArray()
        val key: Key = convertHashToKey(hash)
        val cipher = Cipher.getInstance(CIPHER_AES_ECB_PADDING)
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

    fun decryptionECBMode(encryptedData: String, hash: ByteArray): String {
        val key: Key = convertHashToKey(hash)



        val cipher = Cipher.getInstance(CIPHER_AES_ECB_PADDING) //AES/ECB/PKCS5Padding
        cipher.init(
            Cipher.DECRYPT_MODE,
            key
        )
        val decryptedData: ByteArray = Base64.decode(encryptedData, Base64.DEFAULT)
        val result: ByteArray = cipher.doFinal(decryptedData)
        return String(result)
    }
//[END ECB Mode]

//START CBC Mode]
    fun encryptionCBCMode(userInput: String, hash: ByteArray): String {
        val input: ByteArray = userInput.toByteArray()
        val key: Key = convertHashToKey(hash)
        val cipher = Cipher.getInstance(CIPHER_AES_CBC_PADDING)
        cipher.init(
            Cipher.ENCRYPT_MODE,
            key,
            IvParameterSpec(iv)
        )
        val result: String
        cipher.doFinal(input).let { bytes ->
            result = Base64.encodeToString(bytes, Base64.DEFAULT)
        }
        return result
    }

    fun decryptionCBCMode(encryptedData: String, hash: ByteArray): String {
        val key: Key = convertHashToKey(hash)

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
//[END CBC Mode]

    fun convertHashToKey(sharedSecretHash : ByteArray): Key {
        return SecretKeySpec(sharedSecretHash, KeyProperties.KEY_ALGORITHM_AES)
    }
}