package com.study.cipher

import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AesCipher {
    companion object {
        private var instance: AesCipher? = null

        fun getInstance(): AesCipher {
            if (instance == null) {
                instance = AesCipher()
            }
            return instance!!
        }
    }
    private val aesKeyAlias = "aesAlias"
    private val aesKeyValue = byteArrayOf(
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F
    )
    //Initial Vector
    private val iv = ByteArray(16)

    init {
        setAesKey()
    }

    /**
     *
     */
    private fun setAesKey() {
        try {
            val aesKey = SecretKeySpec(
                aesKeyValue,
                0,
                aesKeyValue.size,
                KeyProperties.KEY_ALGORITHM_AES
            )
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            keyStore.setEntry(
                aesKeyAlias,
                KeyStore.SecretKeyEntry(aesKey),
                KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setRandomizedEncryptionRequired(false) //if it is not, "java.security.InvalidKeyException: IV required when decrypting." occur
                    .build()
            )
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /**
     *
     */
    private fun getAesKey(): SecretKey? {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            return keyStore.getKey(aesKeyAlias, null) as SecretKey
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    /**
     *
     */
    fun encrypt(message: String): String? {
        try {
            val aesKey = getAesKey()
            val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
            cipher.init(
                Cipher.ENCRYPT_MODE,
                aesKey,
                IvParameterSpec(iv)
            )
            return DataTypeConverter.byteArrayToString(cipher.doFinal(message.toByteArray()))
        } catch (e: Exception) {
            e.printStackTrace()
            return  null
        }
    }

    /**
     *
     */
    fun decrypt(message: String): String? {
        try {
            val encryptedMessage = DataTypeConverter.hexStringToByteArray(message)
            val aesKey = getAesKey()

            //cipher
            val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                aesKey,
                IvParameterSpec(iv)
            )

            //encryptedMsgByte(ByteArray) -> decryptedMessage(ByteArray)
            val decryptedMessage = cipher.doFinal(encryptedMessage)

            //ByteArray -> String
            return String(decryptedMessage)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }
}