package com.study.ecdhcipher

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.RequiresApi
import java.math.BigInteger
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class EcdhCipher {
    companion object {
        private var instance: EcdhCipher? = null
        private lateinit var espm: ESPManager
        private lateinit var context: Context

        fun getInstance(context: Context): EcdhCipher? {
            if (instance == null) {
                espm = ESPManager.getInstance(context)!!
                Companion.context = context
                instance = EcdhCipher()
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

    /**
     * ECKeyPair(privateKey/publicKey)를 생성하고 keystore 에 보관한다.
     * AndroidAPI 31 이상 사용 가능
     */
    @RequiresApi(Build.VERSION_CODES.S)
    fun generateECKeyPair() {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )
            val parameterSpec = KeyGenParameterSpec.Builder(
                defaultKeyStoreAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_AGREE_KEY
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

    /**
     * keystore 에서 publicKey 를 가져온다.
     */
    fun getECPublicKey(): String? {
        try {
            val publicKey =
                androidKeyStore.getCertificate(defaultKeyStoreAlias).publicKey as ECPublicKey

            //첫번째 인덱스의 숫자가 0인 경우, 맨 앞 인덱스에 0 이 추가되어 byte[33]이 나오게 됨
            //이런 경우 불필요한 인덱스를 잘라내 byte[32] 를 맞춰주는 작업
            val _affineX = publicKey.w.affineX.toByteArray()
            val _affineY = publicKey.w.affineY.toByteArray()

            val affineX: ByteArray = if (_affineX[0] == 0.toByte()) {
                Arrays.copyOfRange(_affineX, 1, 33)
            } else {
                Arrays.copyOfRange(_affineX, 0, 32)
            }
            val affineY: ByteArray = if (_affineY[0] == 0.toByte()) {
                Arrays.copyOfRange(_affineY, 1, 33)
            } else {
                Arrays.copyOfRange(_affineY, 0, 32)
            }

            //publicKey Uncompressed Form
            //byte[65] = [0x04(1byte)][affineX(32byte)][affineY(32byte)]
            val ecPublicKey: ByteArray = byteArrayOf(0x04) + affineX + affineY

            //ByteArray -> String
            return Base64.encodeToString(ecPublicKey, Base64.NO_WRAP)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    /**
     * SharedSecretKey 을 생성하고 ESP 저장. 그리고 키식별자(keyId)를 반환한다.
     * @param publicKey 상대방의 publicKey
     * @param secureRandom 키식별자와 MessageDigest 에서 사용되는 난수
     * @return 키식별자(keyId)
     */
    fun generateSharedSecretKey(publicKey: String, secureRandom: String): String? {
        try {
            val keyId: String = secureRandom
            val random: ByteArray = Base64.decode(secureRandom, Base64.NO_WRAP)

            //byteArray -> publicKey
            val _friendPublicKey: ByteArray = Base64.decode(publicKey, Base64.NO_WRAP)
            val friendPublicKey: PublicKey = byteArrayToPublicKey(_friendPublicKey)!!

            val myPrivateKey: PrivateKey
            androidKeyStore.getEntry(defaultKeyStoreAlias, null).let { keyStoreEntry ->
                myPrivateKey = (keyStoreEntry as KeyStore.PrivateKeyEntry).privateKey
            }

            //sharedSecretKey
            val sharedSecretKeyBytes = KeyAgreement.getInstance("ECDH").apply {
                init(myPrivateKey)
                doPhase(friendPublicKey, true)
            }.generateSecret()

            //hash(SHA256)
            val hash = MessageDigest.getInstance(KeyProperties.DIGEST_SHA256).apply {
                update(sharedSecretKeyBytes)
            }.digest(random)

            //keySpec
            val secretKeySpec = SecretKeySpec(
                hash,
                KeyProperties.KEY_ALGORITHM_AES
            )

            //sharedSecretKey(String)
            val sharedSecretKeyString = Base64.encodeToString(
                /*encodingKeySpec*/ secretKeySpec.encoded,
                /*padding*/ Base64.NO_WRAP
            )

            //ESP 에 sharedSecretKey 저장
            espm.putString(keyId, sharedSecretKeyString)

            return keyId
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    /**
     * keystore 와 ESP 를 초기화한다.
     */
    fun reset() {
        try {
            androidKeyStore.deleteEntry(defaultKeyStoreAlias)
            espm.removeAll()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /**
     * 난수를 생성한다.
     * @param size 난수 길이
     */
    fun generateRandom(size: Int): String? {
        try {
            return Base64.encodeToString(
                /*secureRandomBytes*/
                ByteArray(size).apply {
                    SecureRandom().nextBytes(this)
                },
                /*padding*/
                Base64.NO_WRAP
            )
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    /**
     * @param keyId ESP 에 저장된 sharedSecretKey 의 식별자
     * @return 삭제 성공 여부. 지워졌다면 true, 아니라면 false
     */
    fun deleteSharedSecretKey(keyId: String): Boolean {
        espm.apply {
            try {
                remove(keyId)
            } catch (e: Exception) {
                return false
            }
            //정상적으로 지워졌는지 확인 후 Boolean 반환한다.
            getString(keyId, "").let { result ->
                return result.isEmpty()
            }
        }
    }

    /**
     * 메시지를 암호화한다.
     * @param message 암호화 시킬 메시지
     * @param keyId
     * @return 암호화된 메시지
     */
    fun encrypt(message: String, keyId: String): String? {
        try {
            //SharedSecretKey
            val encodingSharedSecretKey: String? = espm.getString(keyId, "").ifEmpty {
                return null
            }
            val decodingSharedSecretKey = Base64.decode(encodingSharedSecretKey, Base64.NO_WRAP)

            //KeySpec
            val secretKeySpec = SecretKeySpec(
                decodingSharedSecretKey,
                0,
                decodingSharedSecretKey.size,
                KeyProperties.KEY_ALGORITHM_AES
            )

            //Cipher
            val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
            cipher.init(
                Cipher.ENCRYPT_MODE,
                secretKeySpec,
                IvParameterSpec(iv)
            )

            //encryptedMessage(ByteArray) -> encodingEncryptedMessage(String, Base64 encoding)
            return Base64.encodeToString(
                /*encryptedMessage(ByteArray)*/ cipher.doFinal(message.toByteArray()),
                /*padding*/ Base64.NO_WRAP
            )
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    /**
     * 메시지를 복호화한다.
     * @param encryptedMessage 암호화 시킬 메시지
     * @param keyId sharedSecretKey 식별자
     * @return 복호화된 메시지
     */
    fun decrypt(encryptedMessage: String, keyId: String): String? {
        try {
            //SharedSecretKey
            val encodingSharedSecretKey: String? = espm.getString(keyId, "").ifEmpty {
                return null
            }
            val decodingSharedSecretKey = Base64.decode(encodingSharedSecretKey, Base64.NO_WRAP)

            //SecretKeySpec
            val secretKeySpec = SecretKeySpec(
                decodingSharedSecretKey,
                0,
                decodingSharedSecretKey.size,
                KeyProperties.KEY_ALGORITHM_AES
            )

            //cipher
            val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                secretKeySpec,
                IvParameterSpec(iv)
            )

            //encodingEncryptedMessage(String) -> decodingEncryptedMessage(ByteArray)
            val decodingEncryptedMessage = Base64.decode(
                /*encodingEncryptedMessage(String)*/ encryptedMessage,
                /*padding*/ Base64.NO_WRAP
            )

            //decodingEncryptedMessage(ByteArray) -> decryptedMessage(ByteArray)
            val decryptedMessage = cipher.doFinal(decodingEncryptedMessage)

            //ByteArray -> String
            return String(decryptedMessage)
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }

    /**
     * ECKeyPair 가 keystore 에 있는지 확인한다.
     * @return ECKeyPair 가 있다면 true, 없다면 false
     */
    fun isECKeyPairOnKeyStore(): Boolean {
        try {
            val keyStoreEntry: KeyStore.Entry? =
                androidKeyStore.getEntry(defaultKeyStoreAlias, null)
            return keyStoreEntry != null
        } catch (e: Exception) {
            e.printStackTrace()
            return false
        }
    }

    /**
     * ByteArray 타입 Uncompressed form 으로 publicKey 생성
     * ByteArray affineX, affineY 로 ECPoint 를 생성해 PublicKey 로 복원한다.
     * @param keyByteArray PublicKey ByteArray(Uncompressed Form)
     * @return ECPublicKey
     */
    private fun byteArrayToPublicKey(keyByteArray: ByteArray): PublicKey? {
        try {
            //ByteArray -> String
            val _affineX = DataTypeConverter.byteArrayToString(keyByteArray, 1, 32)
            val _affineY = DataTypeConverter.byteArrayToString(keyByteArray, 33, 32)

            //String -> BigInteger
            val affineX = BigInteger(_affineX, 16)
            val affineY = BigInteger(_affineY, 16)

            //AlgorithmParameters
            val algorithmParameters =
                AlgorithmParameters.getInstance(KeyProperties.KEY_ALGORITHM_EC)
            algorithmParameters.init(ECGenParameterSpec("secp256r1"))

            //ECParameterSpec
            val parameterSpec = algorithmParameters.getParameterSpec(ECParameterSpec::class.java)

            //KeySpec
            val publicKeySpec = ECPublicKeySpec(
                /*ECPoint*/
                ECPoint(affineX, affineY),
                /*ECParameterSpec*/
                parameterSpec
            )

            //publicKey -> ECPublicKey
            return KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC).generatePublic(publicKeySpec) as ECPublicKey
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }
}