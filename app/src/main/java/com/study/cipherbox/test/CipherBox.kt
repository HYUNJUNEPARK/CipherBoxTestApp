package com.study.cipherbox.test

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.RequiresApi
import com.study.cipherbox.sdk.JavaUtil
import com.study.cipherbox.sdk.aos.EncryptedSharedPreferencesManager
import java.math.BigInteger
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.*
import javax.crypto.KeyAgreement
import javax.crypto.spec.SecretKeySpec

//디바이스 계정 한개에 복수의 ECKeyPair 가 필요한 테스트앱에서 사용하는 클래스
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

    fun isECKeyPairOnKeyStore(userId: String): Boolean {
        val keyStoreEntry: KeyStore.Entry? = androidKeyStore.getEntry(userId, null)
        return keyStoreEntry != null
    }


    /**
     * Deprecated Methods
     */


    @RequiresApi(Build.VERSION_CODES.O)
    fun stringToPublicKey(publicKey: String): PublicKey? {
        try {
            val _publicKey = publicKey
            val encoded: ByteArray = java.util.Base64.getDecoder().decode(_publicKey)
            // val _encoded: ByteArray = Base64.decode(_publicKey, Base64.NO_WRAP)
            val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
            val templateForECPublicKey = byteArrayOf(
                0x30, 0x59,
                0x30, 0x13,
                0x06, 0x07, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x02, 0x01,
                0x06, 0x08, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x03, 0x01, 0x07,
                0x03, 0x42, 0x00
            )
            val keySpec = X509EncodedKeySpec(templateForECPublicKey + encoded)
            return keyFactory.generatePublic(keySpec) as ECPublicKey
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    fun publicKeyToString(publicKey: PublicKey): String? {
        try {
            //publicKey -> affineX, affineY -> uncompressed form(string -> byteArray) -> Base64Encoding(byteArray -> string)
            val ecPublicKey = publicKey as ECPublicKey
            //TODO Decimal -> Hex
            val affineX = ecPublicKey.w.affineX
            val affineY = ecPublicKey.w.affineY
            val uncompressedForm_str = "04$affineX$affineY"
            val uncompressedForm_bytes = JavaUtil.hexStringToByteArray(uncompressedForm_str)
            return Base64.encodeToString(uncompressedForm_bytes, Base64.NO_WRAP)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    fun _publicKeyToString(publicKey: PublicKey): String? {
        try {
            //publicKey -> byte
            val _publicKey: ByteArray = publicKey.encoded
            //byte -> string
            return Base64.encodeToString(_publicKey, Base64.NO_WRAP)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    //공개키로 affineX, affineY 생성
    fun getAffineXY(userId: String, publicKey: String): HashMap<String, String>? {
        try {
            //String -> ByteArray
            val uncompressedForm_bytes = Base64.decode(publicKey, Base64.NO_WRAP)
            // bytes[0]: 0x04
            // bytes[1 .. 31]: affineX
            // bytes[32 .. 64]: affineY

            //bytes
            if (uncompressedForm_bytes[0].equals(0)) {
                val affineX = JavaUtil.byteArrayToString(uncompressedForm_bytes, 1, 32)
                val affineY = JavaUtil.byteArrayToString(uncompressedForm_bytes, 32, 32)

                return hashMapOf(
                    "userId" to userId,
                    "affineX" to affineX,
                    "affineY" to affineY
                )
            }
            else {
                val affineX = JavaUtil.byteArrayToString(uncompressedForm_bytes, 1, 32)
                val affineY = JavaUtil.byteArrayToString(uncompressedForm_bytes, 32, 32)

                return hashMapOf(
                    "userId" to userId,
                    "affineX" to affineX,
                    "affineY" to affineY
                )
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    fun _deriveECPublicKeyFromECPoint(affineX: String, affineY: String): PublicKey {
        val affineX = BigInteger(affineX)
        val affineY = BigInteger(affineY)
        val ecPoint = ECPoint(affineX, affineY)
        val keySpec = ECPublicKeySpec(
            ecPoint,
            ecParameterSpec
        )
        val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
        return keyFactory.generatePublic(keySpec)
    }

    //Reference : Elliptic Curve Domain Parameters (https://www.secg.org/sec2-v2.pdf Page9 of 33-34)
    private val ecParameterSpec= with(this) {
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
        ECParameterSpec(curve, g, n, h)
    }

}