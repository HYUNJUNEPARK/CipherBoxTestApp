package com.june.strongboxkey.strongbox

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.*
import java.security.spec.*
import javax.crypto.KeyAgreement
import javax.crypto.spec.SecretKeySpec

class KeyProvider(private val context: Context) {

    private val keyAlias = "androidKeyStoreKey"
    private val keystoreFile = "default_keystore"
    private val storePassword = "storePassword".toCharArray()
    private val keyPassword = "keyPassword".toCharArray()
    private val androidKeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }
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

    //채널 초대한 사람이 사용
    //TODO 반환한 keyId(random) 을 채널 서버 메타 데이터로 올리는 코드 구현이 필요
    fun generateSharedSecretKey(publicKey: PublicKey): String {
        val keyId = generateRandom(32)
        //private key
        val privateKey: PrivateKey
        androidKeyStore.getEntry(keyAlias, null).let { keyStoreEntry ->
            privateKey = (keyStoreEntry as KeyStore.PrivateKeyEntry).privateKey
        }
        //sharedSecretKey
        val sharedSecretKey: Key
        KeyAgreement.getInstance("ECDH").apply {
            init(privateKey)
            doPhase(publicKey, true)
        }.generateSecret().let { _sharedSecret ->
            val messageDigest = MessageDigest.getInstance(KeyProperties.DIGEST_SHA256).apply {
                update(_sharedSecret)
            }
            //random
            val random = Base64.decode(keyId, Base64.DEFAULT)
            val hash = messageDigest.digest(random)
            sharedSecretKey = SecretKeySpec(hash, KeyProperties.KEY_ALGORITHM_AES)
        }

        //update keystore
        defaultKeyStore.setKeyEntry(keyId, sharedSecretKey, keyPassword, null)
        val ksOut: FileOutputStream = context.openFileOutput(keystoreFile, Context.MODE_PRIVATE)
        defaultKeyStore.store(ksOut, storePassword)
        ksOut.close()

        return keyId
    }

    //채널 초대받은 사람이 사용
    //TODO keyId(random) 에 sharedKey 가 저장되어있기 때문에 앱쪽에서 keyId 와 채널 URL 을 연결해주는 DB 구현이 필요
    fun generateSharedSecretKey(publicKey: PublicKey, random: String): String {
        val keyId = random
        //private key
        val privateKey: PrivateKey
        androidKeyStore.getEntry(keyAlias, null).let { keyStoreEntry ->
            privateKey = (keyStoreEntry as KeyStore.PrivateKeyEntry).privateKey
        }
        //random
        val random = Base64.decode(random, Base64.DEFAULT)

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




    //useless
    fun isKeyInKeyStore(keyAlias: String): Boolean {
        return androidKeyStore.containsAlias(keyAlias)
    }

    fun isKeyPairInKeyStore(keyStoreAlias: String): Boolean {
        val keyStoreEntry: KeyStore.Entry? = androidKeyStore.getEntry(keyStoreAlias, null)
        return keyStoreEntry != null
    }
}