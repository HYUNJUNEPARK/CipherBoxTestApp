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

    //reference : Elliptic Curve Domain Parameters (https://www.secg.org/sec2-v2.pdf Page9 of 33-34)
    private fun ecParameterSpec(): ECParameterSpec {
        val p = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
        val a = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)
        val b = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
        val gX = BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16)
        val gY = BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
        val n = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        val h = 1
        val ecField = ECFieldFp(p)
        val curve = EllipticCurve(ecField, a, b)
        val g = ECPoint(gX, gY)
        return ECParameterSpec(curve, g, n, h)
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