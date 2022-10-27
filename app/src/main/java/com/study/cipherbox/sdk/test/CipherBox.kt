package com.study.cipherbox.sdk.test

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.study.cipherbox.sdk.EncryptedSharedPreferencesManager
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement
import javax.crypto.spec.SecretKeySpec

class CipherBox {
    companion object {
        private var instance: CipherBox? = null
        private lateinit var espm: EncryptedSharedPreferencesManager
        private lateinit var context: Context

        fun getInstance(): CipherBox? {
            if (instance == null) {
                espm = EncryptedSharedPreferencesManager.getInstance(context)!!
                context = context
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

    //테스트를 위한 오버로딩 메서드
    //계정마다 keyStoreAlias 를 다르게 등록해 ECKeyPair 식별자로 사용
    fun generateECKeyPair(keyStoreAlias: String) {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )
            val parameterSpec = KeyGenParameterSpec.Builder(
                keyStoreAlias,
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
    }

    //테스트를 위한 오버로딩 메서드
    fun getECPublicKey(keyStoreAlias: String): PublicKey {
        return androidKeyStore.getCertificate(keyStoreAlias).publicKey
    }

    //테스트를 위한 오버로딩 메서드
    @Throws(Exception::class)
    fun generateSharedSecretKey(
        userId:String,
        publicKey: PublicKey,
        nonce: String
    ): String {
        val keyId: String = nonce
        val random: ByteArray = Base64.decode(nonce, Base64.NO_WRAP)

        val privateKey: PrivateKey
        androidKeyStore.getEntry(userId, null).let { keyStoreEntry ->
            privateKey = (keyStoreEntry as KeyStore.PrivateKeyEntry).privateKey
        }

        var sharedSecretKey: String
        KeyAgreement.getInstance("ECDH").apply {
            init(privateKey)
            doPhase(publicKey, true)
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
    }

    fun isECKeyPair(userId: String): Boolean {
        val keyStoreEntry: KeyStore.Entry? = androidKeyStore.getEntry(userId, null)
        return keyStoreEntry != null
    }
}