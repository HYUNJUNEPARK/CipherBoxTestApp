package com.study.cipherbox.sdk

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.konai.sendbirdapisampleapp.strongbox.EncryptedSharedPreferencesManager
import com.konai.sendbirdapisampleapp.strongbox.StrongBox
import com.study.cipherbox.app.KeyPairModel
import java.math.BigInteger
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.*
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
                this.context = context
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
    }

    fun getECPublicKey(): PublicKey {
        return androidKeyStore.getCertificate(defaultKeyStoreAlias).publicKey
    }

    fun generateSharedSecretKey(publicKey: PublicKey, nonce: String): String {
        val keyId: String = nonce
        val random: ByteArray = Base64.decode(nonce, Base64.NO_WRAP)
        val privateKey: PrivateKey
        StrongBox.androidKeyStore.getEntry(defaultKeyStoreAlias, null).let { keyStoreEntry ->
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


    fun resetStrongBox() {
        androidKeyStore.deleteEntry(defaultKeyStoreAlias)
        espm.removeAll()
    }

    fun generateRandom(size: Int): String {
        return ByteArray(size).apply {
            SecureRandom().nextBytes(this)
        }.let { randomBytes ->
            Base64.encodeToString(randomBytes, Base64.NO_WRAP)
        }
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

    fun encrypt(message: String, keyId: String): String {
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
    }

    fun decrypt(message: String, keyId: String): String {
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
    }

    fun isECKeyPair(): Boolean {
        val keyStoreEntry: KeyStore.Entry? = StrongBox.androidKeyStore.getEntry(StrongBox.ecKeyPairAlias, null)
        return keyStoreEntry != null
    }





///////////////////////////////////////////
    var iv_ex_ver: ByteArray? = null

    fun encrypt_ex_ver(message: String, key: ByteArray): String {
        val sharedSecretKey: Key = SecretKeySpec(key, KeyProperties.KEY_ALGORITHM_AES)
        val userInputData: ByteArray = message.toByteArray()
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            sharedSecretKey
        )
        iv_ex_ver = cipher.iv
        val _result: ByteArray = cipher.doFinal(userInputData)
        val result: String = Base64.encodeToString(_result, Base64.DEFAULT)
        return result
    }




    fun decrypt_ex_ver(message: String, key: ByteArray): String {
        val sharedSecretKey: Key = SecretKeySpec(key, KeyProperties.KEY_ALGORITHM_AES)
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            sharedSecretKey,
            IvParameterSpec(iv_ex_ver)
        )
        val decryptedData: ByteArray = Base64.decode(message, Base64.DEFAULT)
        val result: ByteArray = cipher.doFinal(decryptedData)
        return String(result)
    }

    fun generateECKeypair(): KeyPairModel {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC
        )
        keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair = keyPairGenerator.generateKeyPair()
        return KeyPairModel(keyPair.private, keyPair.public)
    }

    fun agreementKey(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKey, true)
        val sharedSecretKey: ByteArray = keyAgreement.generateSecret()
        return hashSHA256(sharedSecretKey)
    }

    private fun hashSHA256(key: ByteArray): ByteArray {
        val hash: ByteArray
        try {
            val messageDigest = MessageDigest.getInstance(KeyProperties.DIGEST_SHA256)
            messageDigest.update(key)
            hash = messageDigest.digest(randomByteArrayGenerator())
        }
        catch (e: CloneNotSupportedException) {
            throw DigestException("$e")
        }
        return hash
    }

    private fun randomByteArrayGenerator(): ByteArray {
        val randomByteArray = ByteArray(32)
        SecureRandom().nextBytes(randomByteArray)
        return randomByteArray
    }






///////////////////////////////////////////

    //not use this method
    //서버에 업로드할 publicKey 를 x, y 좌표로 분해
    fun disassemble(publicKey: PublicKey): HashMap<String, String> {
        val ecPublicKey = publicKey as ECPublicKey
        return hashMapOf(
            "affineX" to ecPublicKey.w.affineX.toString(),
            "affineY" to ecPublicKey.w.affineY.toString()
        )
    }

    //not use this method
    //서버에서 받은 x, y 좌표로 publicKey 생성
    fun assemble(affineX: String, affineY: String): PublicKey {
        val affineX = BigInteger(affineX)
        val affineY = BigInteger(affineY)
        val ecPoint = ECPoint(affineX, affineY)
        val keySpec = ECPublicKeySpec(ecPoint, ecParameterSpec())
        val keyFactory = KeyFactory.getInstance("EC")
        return keyFactory.generatePublic(keySpec)
    }

    //Reference : Elliptic Curve Domain Parameters (https://www.secg.org/sec2-v2.pdf Page9 of 33-34)
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
}