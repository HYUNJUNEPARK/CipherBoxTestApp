package com.june.strongboxkey.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.*
import java.security.spec.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.log

//TODO 예외처리 추가와 단위테스트로 각 메서드의 안정성을 올리는 작업이 반드시 필요함!

class TestStrongBox {
    //싱글톤 패턴
    companion object {

        const val TAG = "testLog"
        //TODO Do not place Android context classes in static fields; this is a memory leak
        private var instance: TestStrongBox? = null
        private lateinit var context: Context

        /**
         * StrongBox SDK 를 사용하기 위한 새로운 라이브러리 인스턴스 생성. 라이브러리 초기화 작업 수행
         *
         * @param _context application context
         * @return Interface 싱글톤 객체
         * TODO exception
         * @throws IllegalArgumentException
         *         제공된 application context 로 부터 확인한 application 이 허용 목록에 없는 경우
         */

        fun getInstance(_context: Context): TestStrongBox {
            return instance ?: synchronized(this) {
                instance ?: TestStrongBox().also { strongBox ->
                    context = _context
                    instance = strongBox
                }
            }
        }

        //기본 유형 키스토어(BKS)를 보관하고 있는 파일 이름으로 해당 파일에는 패스워드가 걸려있습니다.
        val keystoreFile = "testKeystoreFile"
        //기본 유형 키스토어(BKS)를 보관하고 있는 파일을 열기 위한 패스워드입니다.
        val filePassword = "filePassword".toCharArray()
        //기본 유형 키스토어(BKS)에서 보관하고 있는 shared Secret Key 에 접근하기 위한 패스워드입니다.
        val keyEntryPassword = "KeyEntryPassword".toCharArray()
        //안드로이드 키스토어(AndroidKeyStore) 에 저장되어있는 EC Key Pair 의 식별자입니다.
        val keyAlias = "testAndroidKeyStoreKey"
        //안드로이드 키스토어(AndroidKeyStore) : 해당 키스토어에는 사용자의 EC Private Key / EC Public Key 가 저장되어 관리됩니다.


        val androidKeyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }
        //기본 유형 키스토어(BKS) : 패스워드가 걸려있는 파일에 저장되고, 이 키스토어에서는 shared Secret Key 가 저장되어 관리됩니다.
        //File(PW : storePassword) -> keystore 접근 -> KeyEntry(PW: keyPassword) -> sharedSecretKey 접근
        val defaultKeyStore: KeyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            var fis: FileInputStream? = null
            try {
                fis = context.openFileInput(keystoreFile)
            }
            catch (e: Exception){
                load(null)
                return@apply
                //TODO return ?
            }
            load(fis, filePassword)
        }
    }

    //CBC(Cipher Block Chaining) Mode 에서 첫번째 암호문 대신 사용되는 IV(Initial Vector)로 0으로 초기화 되어있습니다.
    private val iv: ByteArray = ByteArray(16)


    /**
     * StrongBox 에 저장된 모든 보안 데이터를 삭제하고 초기화
     */
    fun restStrongBox() {

    }

    /**
     * EC 키 쌍(EC Private Key/EC Public Key)을 생성. 생성된 키 쌍은 StrongBox 의 안전한 저장소(AndroidKeyStore)에 저장
     * 안드로이드 API 31 이상 사용 가능
     *
     * TODO User Exception 정의. Key Pair 생성에 실패한 경우. 재생성 조건을 충족하지 못한 경우.
     */
    fun generateECKeyPair() {
        try {
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
        } catch (e: Exception) {
            //User Exception 정의
        }
    }

    /**
     * AndroidKeyStore 에 저장되어 있는 EC 키 쌍 중 공개키를 반환
     *
     * @return PublicKey
     * TODO User Exception 정의.
     */
    fun getECPublicKey(): PublicKey? {
        return androidKeyStore.getCertificate(keyAlias).publicKey

    }

    /**
     * Nonce 로 사용될 랜덤 데이터를 생성 후 반환
     *
     * 생성된 랜덤 데이터 사용처
     * 1) 해시를 만들 때 사용
     * 2) keyId 로 사용
     *
     * @param size 랜덤 데이터의 길이를 입력합니다.
     * @return byteArray 랜덤 데이터를 String 으로 바꾼 뒤 반환합니다.
     * TODO User Exception 정의.
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
     * TODO User Exception 정의.
     */
    fun generateSharedSecretKey(publicKey: PublicKey, nonce: String): String {
        val keyId:String = nonce
        val random:ByteArray = Base64.decode(nonce, Base64.DEFAULT)

        val privateKey: PrivateKey
        androidKeyStore.getEntry(keyAlias, null).let { keyStoreEntry ->
            privateKey = (keyStoreEntry as KeyStore.PrivateKeyEntry).privateKey
        }

        var sharedSecretKey: Key
        KeyAgreement.getInstance("ECDH").apply {
            init(privateKey)
            doPhase(publicKey, true)
        }.generateSecret().let { _sharedSecret ->
            val messageDigest = MessageDigest.getInstance(KeyProperties.DIGEST_SHA256).apply {
                update(_sharedSecret)
            }
            val hash = messageDigest.digest(random)
            sharedSecretKey = SecretKeySpec(
                hash,
                KeyProperties.KEY_ALGORITHM_AES
            )
        }

        defaultKeyStore.setKeyEntry(keyId, sharedSecretKey, keyEntryPassword, null)
        val ksOut: FileOutputStream = context.openFileOutput(keystoreFile, Context.MODE_PRIVATE)
        defaultKeyStore.store(ksOut, filePassword)
        ksOut.close()

        //사용이 끝난 shared Secret Key 는 0 으로 초기화
//        sharedSecretKey = SecretKeySpec(
//            ByteArray(16),
//            KeyProperties.KEY_ALGORITHM_AES
//        )

        //privateKey.destroy()
        //TODO init 0 private key ??
        //TODO overwrite useless key

        return keyId
    }

    /**
     * AndroidKeyStore 에 저장되어 있는 ECKeyPair 를 삭제하는 메서드입니다.
     * 사용자가 갖고있는 KeyPair 갱신을 원한 때 호출합니다.
     * 해당 메서드를 사용한 후 사용자에게 새로운 ECKeyPair 를 발급해 주는 기능 구현이 필요합니다.
     *
     * @return keyPair 가 안전하게 삭제되었다면 true 를 그렇지 않다면 false 를 반환합니다.
     * TODO User Exception 정의.
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

    //TODO 여기서 잘 안지워지는 듯함!



    fun deleteSharedSecretKey(keyId: String): Boolean {
        try {
            //TODO 이거 말고 다르게 지우는 방법이 있을 거 같음 안지워짐 ...
            //defaultKeyStore.deleteEntry(keyId)

//            var fis: FileInputStream? = null
//            try {
//                fis = context.openFileInput(keystoreFile)
//            }
//            catch (e: Exception){
//                e.printStackTrace()
//            }
//            defaultKeyStore.load(fis, filePassword)
//            fis?.close()

            defaultKeyStore.deleteEntry(keyId)

            if(defaultKeyStore.containsAlias(keyId)) {
                Log.d(TAG, "키 안지워짐")
            } else {
                Log.d(TAG, "키 지워짐")
            }

            for (i in defaultKeyStore.aliases()) {
                Log.d(TAG, "defaultKeyStore.aliases(): $i")
            }

            val key: Key? = defaultKeyStore.getKey(keyId, keyEntryPassword)
            Log.d(TAG, "key: Key? $key")




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
//        var fis: FileInputStream? = null
//        try {
//            fis = context.openFileInput(keystoreFile)
//        }
//        catch (e: Exception){
//            e.printStackTrace()
//        }
//        defaultKeyStore.load(fis, filePassword)
//        fis?.close()

        if(defaultKeyStore.containsAlias(keyId)) {
            Log.d(TAG, "encryption 키 있음")
        } else {
            Log.d(TAG, "encryption 키 없음")
        }


        val sharedSecretKey = defaultKeyStore.getKey(keyId, keyEntryPassword)
        Log.d(TAG, "keyId $keyId |||| encrypt: $sharedSecretKey")
        //TODO

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
        defaultKeyStore.load(fis, filePassword)
        fis?.close()
        val sharedSecretKey = defaultKeyStore.getKey(keyId, keyEntryPassword)

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