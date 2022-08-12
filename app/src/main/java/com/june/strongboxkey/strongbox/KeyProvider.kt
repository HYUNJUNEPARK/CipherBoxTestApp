package com.june.strongboxkey.strongbox

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.*
import java.security.spec.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class KeyProvider(private val context: Context) {
    private val iv: ByteArray = ByteArray(16)
    //
    private val keyAlias = "androidKeyStoreKey"
    //
    private val keystoreFile = "default_keystore"
    //
    private val storePassword = "storePassword".toCharArray()
    //
    private val keyPassword = "keyPassword".toCharArray()
    //
    private val androidKeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }
    //
    private val defaultKeyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
        var fis: FileInputStream? = null
        try {
            fis = context.openFileInput(keystoreFile)
        }
        catch (e: Exception){
            load(null)
        }
        load(fis, storePassword)
    }

//[START Generate Key]
    //TODO Error keyAgreement.init(myPrivateKey) -> USE Android 12, API 31 Device if not InvalidKeyException: Keystore operation failed
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

    fun getECPublicKey(): PublicKey? {
        return androidKeyStore.getCertificate(keyAlias).publicKey
    }

    fun generateRandom(size: Int): String {
        val random = ByteArray(size).apply {
            SecureRandom().nextBytes(this)
        }.let { randomBytes ->
            Base64.encodeToString(randomBytes, Base64.DEFAULT)
        }
        return random
    }

    //채널 초대받은 사람이 사용
    //TODO keyId(random) 에 sharedKey 가 저장되어있기 때문에 앱쪽에서 keyId 와 채널 URL 을 연결해주는 DB 구현이 필요
    //채널 초대한 사람이 사용
    //TODO 반환한 keyId(random) 을 채널 서버 메타 데이터로 올리는 코드 구현이 필요
    fun generateSharedSecretKey(publicKey: PublicKey, nonce: String): String {
        val keyId:String = nonce

        //private key
        val privateKey: PrivateKey
        androidKeyStore.getEntry(keyAlias, null).let { keyStoreEntry ->
            privateKey = (keyStoreEntry as KeyStore.PrivateKeyEntry).privateKey
        }

        //random
        val random:ByteArray = Base64.decode(nonce, Base64.DEFAULT)

        //sharedSecretKey
        val sharedSecretKey: Key
        KeyAgreement.getInstance("ECDH").apply {
            init(privateKey)
            doPhase(publicKey, true)
        }.generateSecret().let { _sharedSecret ->
            val messageDigest = MessageDigest.getInstance(KeyProperties.DIGEST_SHA256).apply {
                update(_sharedSecret)
            }
            val hash = messageDigest.digest(random)
            sharedSecretKey = SecretKeySpec(hash, KeyProperties.KEY_ALGORITHM_AES)
        }

        //update keystore
        defaultKeyStore.setKeyEntry(keyId, sharedSecretKey, keyPassword, null)

        //TODO sharedSecretKey -> init 0 byteArray

        val ksOut: FileOutputStream = context.openFileOutput(keystoreFile, Context.MODE_PRIVATE)
        defaultKeyStore.store(ksOut, storePassword)
        ksOut.close()

        return keyId
    }

    fun deleteECKeyPair(): Boolean {
        try {
            androidKeyStore.deleteEntry(keyAlias)
        }
        catch (e: Exception) {
            throw Exception("keystore key is deleted failed $e")
        }
        return true
    }

    fun encrypt(message: String, keyId: String): String {
        //default keystore 에 저장되어 있는 shared secret key 로드
        var fis: FileInputStream? = null
        try {
            fis = context.openFileInput(keystoreFile)
        }
        catch (e: Exception){
            e.printStackTrace()
        }
        defaultKeyStore.load(fis, storePassword)
        fis?.close()
        val sharedSecretKey = defaultKeyStore.getKey(keyId, keyPassword)

        //메시지 암호화
        val encryptedMessage: String
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            sharedSecretKey,
            IvParameterSpec(iv)
        )
        cipher.doFinal(message.toByteArray()).let { encryption ->
            encryptedMessage = Base64.encodeToString(encryption, Base64.DEFAULT)
        }

        return encryptedMessage
    }

    //TODO hash -> keyId: String
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



    //tempary
    fun getKey(keyAlias: String): Key {
        var fis: FileInputStream? = null
        try {
            fis = context.openFileInput(keystoreFile)
        }
        catch (e: Exception){
            e.printStackTrace()
        }
        defaultKeyStore.load(fis, storePassword)
        fis?.close()
        return defaultKeyStore.getKey(keyAlias, keyPassword)
    }



}