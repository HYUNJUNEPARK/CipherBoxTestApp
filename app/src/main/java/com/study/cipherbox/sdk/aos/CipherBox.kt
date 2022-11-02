package com.study.cipherbox.sdk.aos

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class CipherBox {
    companion object {
        private var instance: CipherBox? = null
        private lateinit var espm: EncryptedSharedPreferencesManager
        private lateinit var context: Context

        fun getInstance(context: Context): CipherBox? {
            if (instance == null) {
                espm = EncryptedSharedPreferencesManager.getInstance(context)!!
                Companion.context = context
                instance = CipherBox()
            }
            return instance
        }
    }

    //안드로이드 키스토어(AndroidKeyStore)에 저장되어있는 EC 키쌍의 식별자
    private val defaultKeyStoreAlias = "defaultKeyStoreAlias"

    //안드로이드 키스토어(AndroidKeyStore) : 해당 키스토어에 사용자의 EC 키쌍이 저장되어 있음
    private val androidKeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    //CBC(Cipher Block Chaining)Mode 에서 첫번째 암호문 대신 사용되는 IV(Initial Vector)로 0으로 초기화되어 있음
    private val iv: ByteArray = ByteArray(16)

    //AndroidAPI 31 이상 사용 가능
    fun generateECKeyPair() {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )
            val parameterSpec = KeyGenParameterSpec.Builder(
                defaultKeyStoreAlias,
                KeyProperties.PURPOSE_ENCRYPT or
                        KeyProperties.PURPOSE_DECRYPT or
                        KeyProperties.PURPOSE_AGREE_KEY
            ).run {
                setUserAuthenticationRequired(false)
                ECGenParameterSpec("secp256r1")
                build()
            }
            keyPairGenerator.initialize(parameterSpec)
            keyPairGenerator.generateKeyPair()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun getECPublicKey(): String? {
        try {
            val publicKey = androidKeyStore.getCertificate(defaultKeyStoreAlias).publicKey as ECPublicKey

            val _affineX = publicKey.w.affineX.toByteArray()
            val _affineY = publicKey.w.affineY.toByteArray();

            // TODO: check length
            val baEcPublicKey = byteArrayOf(0x04) + _affineX + _affineY

            return Base64.encodeToString(baEcPublicKey, Base64.NO_WRAP)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    fun generateSharedSecretKey(publicKey: String, nonce: String): String? {
        try {
            val keyId: String = nonce
            val baECPublicKey = Base64.decode(publicKey, Base64.NO_WRAP)
            val ecPublicKey = ECKeyUtil.deriveECPublicKeyFromECPoint(baECPublicKey)

            val random: ByteArray = Base64.decode(nonce, Base64.NO_WRAP)
            val privateKey: PrivateKey
            androidKeyStore.getEntry(defaultKeyStoreAlias, null).let { keyStoreEntry ->
                privateKey = (keyStoreEntry as KeyStore.PrivateKeyEntry).privateKey
            }
            var sharedSecretKey: String
            KeyAgreement.getInstance("ECDH").apply {
                init(privateKey)
                doPhase(ecPublicKey, true)
            }.generateSecret().let { _sharedSecret ->
                val messageDigest = MessageDigest.getInstance(KeyProperties.DIGEST_SHA256).apply {
                    update(_sharedSecret)
                }
                val hash = messageDigest.digest(random)
                SecretKeySpec(
                    hash,
                    KeyProperties.KEY_ALGORITHM_AES
                ).let { secretKeySpec ->
                    sharedSecretKey = Base64.encodeToString(secretKeySpec.encoded, Base64.NO_WRAP)
                }
            }
            espm.putString(keyId, sharedSecretKey)
            return keyId
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    fun reset() {
        try {
            androidKeyStore.deleteEntry(defaultKeyStoreAlias)
            espm.removeAll()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun generateRandom(size: Int): String? {
        try {
            return ByteArray(size).apply {
                SecureRandom().nextBytes(this)
            }.let { randomBytes ->
                Base64.encodeToString(randomBytes, Base64.NO_WRAP)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    //keyId에 해당하는 sharedSecretKey 삭제
    //지워졌다면 true, 아니라면 false
    fun deleteSharedSecretKey(keyId: String): Boolean {
        espm.apply {
            try {
                remove(keyId)
            }
            catch (e: Exception) {
                return false
            }
            getString(keyId, "").let { result ->
                return result == ""
            }
        }
    }

    fun encrypt(message: String, keyId: String): String? {
        try {
            val iv = ByteArray(16)
            var encodedSharedSecretKey: String? =
                if (espm.getString(keyId, "") == "") {
                    null
                }
                else {
                    espm.getString(keyId, "")
                }

            val encryptedMessage: String
            Base64.decode(encodedSharedSecretKey, Base64.NO_WRAP).let { decodedKey ->
                SecretKeySpec(
                    decodedKey,
                    0,
                    decodedKey.size,
                    KeyProperties.KEY_ALGORITHM_AES
                ).let { secretKeySpec ->
                    val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
                    cipher.init(
                        Cipher.ENCRYPT_MODE,
                        secretKeySpec,
                        IvParameterSpec(iv)
                    )
                    cipher.doFinal(message.toByteArray()).let { _encryptedMessage ->
                        encryptedMessage = Base64.encodeToString(_encryptedMessage, Base64.NO_WRAP)
                    }
                }
            }
            return encryptedMessage
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    fun decrypt(message: String, keyId: String): String? {
        try {
            val iv = ByteArray(16)
            var encodedSharedSecretKey: String? = espm.getString(keyId, "").ifEmpty { null }
            var decryptedMessage: ByteArray
            Base64.decode(encodedSharedSecretKey, Base64.NO_WRAP).let { decodedKey ->
                SecretKeySpec(
                    decodedKey,
                    0,
                    decodedKey.size,
                    KeyProperties.KEY_ALGORITHM_AES
                ).let { secretKeySpec ->
                    val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
                    cipher.init(
                        Cipher.DECRYPT_MODE,
                        secretKeySpec,
                        IvParameterSpec(iv)
                    )
                    Base64.decode(message, Base64.NO_WRAP).let { decryption ->
                        decryptedMessage = cipher.doFinal(decryption)
                    }
                }
            }
            return String(decryptedMessage)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    fun isECKeyPair(): Boolean {
        try {
            val keyStoreEntry: KeyStore.Entry? = androidKeyStore.getEntry(defaultKeyStoreAlias, null)
            return keyStoreEntry != null
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return false
    }
}