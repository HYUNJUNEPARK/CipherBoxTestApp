package com.june.strongboxkey.strongbox.tmporary

import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.DigestException
import java.security.Key
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class Deprecated {
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

    private fun hashSHA256(key: ByteArray, randomNumber: ByteArray): ByteArray {
        val hash: ByteArray
        try {
            val messageDigest = MessageDigest.getInstance("SHA-256")
            messageDigest.update(key)
            hash = messageDigest.digest(randomNumber)
        }
        catch (e: CloneNotSupportedException) {
            throw DigestException("$e")
        }
        return hash
    }

    //useless??
    private val androidKeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    fun isKeyInKeyStore(keyAlias: String): Boolean {
        return androidKeyStore.containsAlias(keyAlias)
    }

    fun isKeyPairInKeyStore(keyStoreAlias: String): Boolean {
        val keyStoreEntry: KeyStore.Entry? = androidKeyStore.getEntry(keyStoreAlias, null)
        return keyStoreEntry != null
    }





//    //채널 초대한 사람이 사용
//    //TODO 반환한 keyId(random) 을 채널 서버 메타 데이터로 올리는 코드 구현이 필요
//    fun generateSharedSecretKey(publicKey: PublicKey): String {
//
//
//        val keyId = generateRandom(32)
//        //private key
//        val privateKey: PrivateKey
//        androidKeyStore.getEntry(keyAlias, null).let { keyStoreEntry ->
//            privateKey = (keyStoreEntry as KeyStore.PrivateKeyEntry).privateKey
//        }
//        //sharedSecretKey
//        val sharedSecretKey: Key
//        KeyAgreement.getInstance("ECDH").apply {
//            init(privateKey)
//            doPhase(publicKey, true)
//        }.generateSecret().let { _sharedSecret ->
//            val messageDigest = MessageDigest.getInstance(KeyProperties.DIGEST_SHA256).apply {
//                update(_sharedSecret)
//            }
//            //random
//            val random = Base64.decode(keyId, Base64.DEFAULT)
//            val hash = messageDigest.digest(random)
//            sharedSecretKey = SecretKeySpec(hash, KeyProperties.KEY_ALGORITHM_AES)
//        }
//
//        //update keystore
//        defaultKeyStore.setKeyEntry(keyId, sharedSecretKey, keyPassword, null)
//        val ksOut: FileOutputStream = context.openFileOutput(keystoreFile, Context.MODE_PRIVATE)
//        defaultKeyStore.store(ksOut, storePassword)
//        ksOut.close()
//
//        return keyId
//    }
}