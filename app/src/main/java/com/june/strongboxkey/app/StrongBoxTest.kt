package com.june.strongboxkey.app

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

//Strong Box SDK 를 테스트하기 위한 클래스

class StrongBoxTest {
    //싱글톤 패턴
    companion object {
        private var instance: StrongBoxTest? = null
        private lateinit var context: Context

        fun getInstance(_context: Context): StrongBoxTest {
            return instance ?: synchronized(this) {
                instance ?: StrongBoxTest().also {
                    context = _context
                    instance = it
                }
            }
        }
    }

    //CBC(Cipher Block Chaining) Mode 에서 첫번째 암호문 대신 사용되는 IV(Initial Vector)로 0으로 초기화 되어있습니다.
    private val iv: ByteArray = ByteArray(16)
    //기본 유형 키스토어(BKS)를 보관하고 있는 파일 이름으로 해당 파일에는 패스워드가 걸려있습니다.
    private val keystoreFile = "test_default_keystore"
    //기본 유형 키스토어(BKS)를 보관하고 있는 파일을 열기 위한 패스워드입니다.
    private val storePassword = "test_defaultStorePassword".toCharArray()
    //기본 유형 키스토어(BKS)에서 보관하고 있는 shared Secret Key 에 접근하기 위한 패스워드입니다.
    private val keyPassword = "test_defaultKeyPassword".toCharArray()
    //안드로이드 키스토어(AndroidKeyStore) 에 저장되어있는 EC Key Pair 의 식별자입니다.
    private val keyAlias = "test_androidKeyStoreKey"
    //안드로이드 키스토어(AndroidKeyStore) : 해당 키스토어에는 사용자의 EC Private Key / EC Public Key 가 저장되어 관리됩니다.
    private val androidKeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }
    //기본 유형 키스토어(BKS) : 패스워드가 걸려있는 파일에 저장되고, 이 키스토어에서는 shared Secret Key 가 저장되어 관리됩니다.
    //File(PW : storePassword) -> keystore 접근 -> KeyEntry(PW: keyPassword) -> sharedSecretKey 접근
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
    /**
     * EC Private Key/EC Public Key 를 생성하고 안드로이드 키스토어(AndroidKeyStore) 에 저장해주는 메서드입니다.
     * 안드로이드 API 31 이상 사용이 가능합니다.
     */
    fun generateECKeyPair() {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )
        val parameterSpec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or
                    KeyProperties.PURPOSE_DECRYPT or
                    KeyProperties.PURPOSE_AGREE_KEY
        ).run {
            setUserAuthenticationRequired(false)
            ECGenParameterSpec("secp256r1") //curve type
            build()
        }
        keyPairGenerator.initialize(parameterSpec)
        keyPairGenerator.generateKeyPair()
    }

    /**
     * 안드로이드 키스토어(AndroidKeyStore) 에 저장되어 있는 EC Public Key 를 가져오는 메서드입니다.
     *
     * @return PublicKey
     */
    fun getECPublicKey(): PublicKey? {
        return androidKeyStore.getCertificate(keyAlias).publicKey
    }

    /**
     * 랜덤한 byteArray 를 생성해 주는 메서드입니다.
     *
     * 생성된 byteArray 사용처
     * 1) 해시를 만들 때 사용
     * 2) keyId 로 사용
     *
     * @param size byteArray 의 길이를 입력합니다.
     * @return byteArray 를 String 타입으로 바꾼 뒤 반환합니다.
     */
    fun generateRandom(size: Int): String {
        val random = ByteArray(size).apply {
            SecureRandom().nextBytes(this)
        }.let { randomBytes ->
            Base64.encodeToString(randomBytes, Base64.DEFAULT)
        }
        return random
    }

    /**
     * 나의 Private Key, 대화 상대의 Public Key 그리고 random byteArray 를 사용해 Shared Secret Key 를 만들고
     * 이를 기본 유형 키스토어(defaultKeyStore, BKS) 에 저장하는 메서드입니다.
     *
     * a. 채널을 초대한 사람이 해당 메서드를 사용할 때
     * -> keyId 를 채널의 메타데이터로 업로드하는 기능 구현이 필요
     * -> keyId 와 채널 URL 주소를 매핑해주는 로컬 DB 구현이 필요
     *
     * b. 채널 초대받은 사람이 해당 메서드를 사용할 때
     * -> 채널 메타데이터로부터 데이터를 가져와 사용 파라미터로 nonce 로 사용
     * -> keyId 와 채널 URL 주소를 매핑해주는 로컬 DB 구현이 필요
     *
     * @param publicKey 대화 상대의 Public Key 를 의미하며, 서버로 부터 받아 온 데이터를 사용합니다.
     * @param nonce random byteArray 를 의미하며 해시를 만들 때 사용합니다.
     * @return 문자열 타입의 keyId 를 반환하며, keyId 는 키스토어에서 Shared Secret Key 를 가져올 때 사용헙나다.
     */
    fun generateSharedSecretKey(publicKey: PublicKey, nonce: String): String {
        val keyId:String = nonce
        val privateKey: PrivateKey
        androidKeyStore.getEntry(keyAlias, null).let { keyStoreEntry ->
            privateKey = (keyStoreEntry as KeyStore.PrivateKeyEntry).privateKey
        }
        val random:ByteArray = Base64.decode(nonce, Base64.DEFAULT)
        var sharedSecretKey: Key
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
        defaultKeyStore.setKeyEntry(keyId, sharedSecretKey, keyPassword, null)
        sharedSecretKey = SecretKeySpec(ByteArray(16), KeyProperties.KEY_ALGORITHM_AES)
        val ksOut: FileOutputStream = context.openFileOutput(keystoreFile, Context.MODE_PRIVATE)
        defaultKeyStore.store(ksOut, storePassword)
        ksOut.close()

        //TODO init 0000000 private key
        //TODO init 0000000 shared secret key

        return keyId
    }

    /**
     * AndroidKeyStore 에 저장되어 있는 ECKeyPair 를 삭제하는 메서드입니다.
     * 사용자가 갖고있는 KeyPair 갱신을 원한 때 호출합니다.
     * 해당 메서드를 사용한 후 사용자에게 새로운 ECKeyPair 를 발급해 주는 기능 구현이 필요합니다.
     *
     * @return keyPair 가 안전하게 삭제되었다면 true 를 그렇지 않다면 false 를 반환합니다.
     */
    fun deleteECKeyPair(): Boolean {
        try {
            androidKeyStore.deleteEntry(keyAlias)
        }
        catch (e: Exception) {
            e.printStackTrace()
            return false
        }
        return true
    }

    /**
     * 기본 유형 키스토어(BKS)에 저장되어 있는 SharedSecretKey 를 삭제하는 메서드입니다.
     *
     * @param keyId 삭제할 SharedSecretKey 의 식별자입니다.
     * @return SharedSecretKey 가 안전하게 삭제되었다면 true 를 그렇지 않다면 false 를 반환합니다.
     */
    fun deleteSharedSecretKey(keyId: String): Boolean {
        try {
            defaultKeyStore.deleteEntry(keyId)
        }
        catch (e: Exception) {
            return false
        }
        return  true
    }

    /**
     * 기본 유형 키스토어(KeyStore.getDefaultType()) 에서 sharedSecretKey 를 가져와 원본 메시지를 암호화하는 메서드입니다.
     *
     * @param message 암호화 진행전 원본 메시지입니다.
     * @param keyId 키스토어에서 sharedSecretKey 를 가져오기 위해 필요한 식별자입니다.
     * @return 암호화된 메시지를 반환합니다.
     */
    fun encrypt(message: String, keyId: String): String {
        //sharedSecretKey
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

    /**
     * 기본 유형 키스토어(KeyStore.getDefaultType()) 에서 sharedSecretKey 를 가져와 원본 메시지를 암호화하는 메서드입니다.
     *
     * @param message 복호화를 하기 위한 암호화된 메시지입니다.
     * @param keyId 키스토어에서 sharedSecretKey 를 가져오기 위해 필요한 식별자입니다.
     * @return 복호화된 원본 메시지를 반환합니다.
     */
    fun decrypt(message: String, keyId: String): String {
        //sharedSecretKey
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

        //메시지 복호화
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            sharedSecretKey,
            IvParameterSpec(iv)
        )
        val decryptedMessage: ByteArray
        Base64.decode(message, Base64.DEFAULT).let { decryption ->
            decryptedMessage = cipher.doFinal(decryption)
        }
        return String(decryptedMessage)
    }
}