package com.june.strongboxkey.util

import android.util.Base64
import android.util.Log
import com.june.strongboxkey.constant.Constants
import com.june.strongboxkey.constant.Constants.CIPHER_CBC_ALGORITHM
import com.june.strongboxkey.constant.Constants.CIPHER_ECB_ALGORITHM
import com.june.strongboxkey.constant.Constants.IV
import java.security.Key
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AESUtils {
    //ECB Mode
    fun encryptionECBMode(userInputData: String, hash: ByteArray): String {
        val userInputData: ByteArray = userInputData.toByteArray()
        val key: Key = byteArrayToKey(hash)
        val cipher = Cipher.getInstance(CIPHER_ECB_ALGORITHM) //AES/ECB/PKCS5Padding
        cipher.init(
            Cipher.ENCRYPT_MODE,
            key
        )
        val _result: ByteArray = cipher.doFinal(userInputData)
        val result: String = Base64.encodeToString(_result, Base64.DEFAULT)
        return result
    }

    fun decryptionECBMode(encryptedData: String, hash: ByteArray): String {
        val key: Key = byteArrayToKey(hash)
        val cipher = Cipher.getInstance(CIPHER_ECB_ALGORITHM) //AES/ECB/PKCS5Padding
        cipher.init(
            Cipher.DECRYPT_MODE,
            key
        )
        val decryptedData: ByteArray = Base64.decode(encryptedData, Base64.DEFAULT)
        val result: ByteArray = cipher.doFinal(decryptedData)
        return String(result)
    }


    private fun byteArrayToKey(sharedSecretKeyHash : ByteArray): Key {
        return SecretKeySpec(sharedSecretKeyHash, Constants.KEY_ALGORITHM)
    }

    //CBC Mode
    fun encryptionCBCMode(userInputData: String, hash: ByteArray): String {
        val key: Key = byteArrayToKey(hash)
        val userInputData: ByteArray = userInputData.toByteArray()
        val cipher = Cipher.getInstance(CIPHER_CBC_ALGORITHM) //AES/CBC/PKCS7Padding
        cipher.init(
            Cipher.ENCRYPT_MODE,
            key
        )
        IV = cipher.iv

        val _result: ByteArray = cipher.doFinal(userInputData)
        val result: String = Base64.encodeToString(_result, Base64.DEFAULT)

        return result
    }

    fun decryptionCBCMode(encryptedData: String, hash: ByteArray): String {
        val key: Key = byteArrayToKey(hash)
        val cipher = Cipher.getInstance(CIPHER_CBC_ALGORITHM) //AES/CBC/PKCS7Padding
        cipher.init(
            Cipher.DECRYPT_MODE,
            key,
            IvParameterSpec(IV)
        )
        val decryptedData: ByteArray = Base64.decode(encryptedData, Base64.DEFAULT)

        //TODO
        val result: ByteArray = cipher.doFinal(decryptedData)

/*
Caused by: javax.crypto.BadPaddingException: error:1e000065:Cipher functions:OPENSSL_internal:BAD_DECRYPT
-PKCS5padding 사용
-companion object 블럭 key 선언 후 사용

  1.2. javax.crypto.BadPaddingException: Given final block not properly padded
     → 암호화된 구문을 복호화할 때 발생할 수 있는 오류로, 암호화 때 사용한 비밀키와 복호화 할 때의 비밀키가
        일치하지 않았을 때 발생

javax.crypto.BadPaddingException: error:1e000065:Cipher functions:OPENSSL_internal:BAD_DECRYPT
https://stackoverflow.com/questions/52148318/javax-crypto-badpaddingexception-error1e000065cipher-functionsopenssl-intern

*/
        return "aaaaaa"
        //return String(result)
    }


}