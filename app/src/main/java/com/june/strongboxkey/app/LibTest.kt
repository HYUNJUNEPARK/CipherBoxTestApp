package com.june.strongboxkey.app

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.math.BigInteger
import java.security.*
import java.security.spec.*
import javax.crypto.KeyAgreement

class LibTest {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private val keyAlias = "testKey"

//[START Generate Key]
    //TODO Error keyAgreement.init(myPrivateKey) -> USE Android 12, API 31 Device if not InvalidKeyException: Keystore operation failed
    //한 기기에 복수의 키쌍을 두고 싶다면 keyAlias 를 메서드의 파라미터로 구조를 바꿔 사용

    fun generateECKeyPair() {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )

        val parameterSpec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or
                    KeyProperties.PURPOSE_DECRYPT or
                    KeyProperties.PURPOSE_AGREE_KEY //Field requires API level 31 (current min is 23)
        ).run {
            setUserAuthenticationRequired(false)
            ECGenParameterSpec("secp256r1") //curve type
            build()
        }
        keyPairGenerator.initialize(parameterSpec)
        keyPairGenerator.generateKeyPair()
    }

    //TODO 앱에서 구현해야하는 함수
//    fun generatePublicKeyByECPoint(affineX: BigInteger, affineY: BigInteger): PublicKey {
//        val ecPoint = ECPoint(affineX, affineY)
//        val keySpec = ECPublicKeySpec(ecPoint, ecParameterSpec())
//        val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
//        return keyFactory.generatePublic(keySpec)
//    }
//[END Generate Key]

    //[START Get Key]
    fun getECPublicKey(): PublicKey? {
        return keyStore.getCertificate(keyAlias).publicKey
    }

//    fun getECPrivateKey(): PrivateKey? {
//        val keyStoreEntry = keyStore.getEntry(keyAlias, null)
//        return (keyStoreEntry as KeyStore.PrivateKeyEntry).privateKey
//    }
//[END Get Key]

    //[START Delete Key]
    fun deleteECKeyPair(): Boolean {
        try {
            keyStore.deleteEntry(keyAlias)
        }
        catch (e: Exception) {
            throw Exception("keystore key is deleted failed $e")
        }
        return true
    }
//[END Delete Key]

    fun isKeyInKeyStore(keyAlias: String): Boolean {
        return keyStore.containsAlias(keyAlias)
    }

    fun isKeyPairInKeyStore(keyStoreAlias: String): Boolean {
        val keyStoreEntry: KeyStore.Entry? = keyStore.getEntry(keyStoreAlias, null)
        return keyStoreEntry != null
    }



    //TODO Error keyAgreement.init(myPrivateKey) -> USE Android 12, API 31 Device if not InvalidKeyException: Keystore operation failed
    //채널 초대한 사람이 사용
    fun generateSharedSecretKey(publicKey: PublicKey) {

    }

    //채널 초대받은 사람이 사용
    fun generateSharedSecretKey(publicKey: PublicKey, random: String): ByteArray {
        val privateKey: PrivateKey
        keyStore.getEntry(keyAlias, null).let { keyStoreEntry ->
            privateKey = (keyStoreEntry as KeyStore.PrivateKeyEntry).privateKey
        }

        val random = Base64.decode(random, Base64.DEFAULT)

        val sharedSecret: ByteArray
        try {
            KeyAgreement.getInstance("ECDH").apply {
                init(privateKey)
                doPhase(publicKey, true)
            }.generateSecret().let { _sharedSecret ->
                val messageDigest = MessageDigest.getInstance(KeyProperties.DIGEST_SHA256).apply {
                    update(_sharedSecret)
                }
                sharedSecret = messageDigest.digest(random)
            }
        }
        catch (e : Exception) {
            throw KeyException("$e")
        }
        catch (e: CloneNotSupportedException) {
            throw DigestException("$e")
        }
        return sharedSecret
    }

    fun getRandom(): String {
        val random = ByteArray(32).apply {
            SecureRandom().nextBytes(this)
        }.let { randomBytes ->
            Base64.encodeToString(randomBytes, Base64.DEFAULT)
        }
        return random
    }
}