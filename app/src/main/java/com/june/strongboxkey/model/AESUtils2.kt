package com.june.strongboxkey.model

import android.util.Base64
import kotlin.Throws
import com.june.strongboxkey.model.AESUtils2
import java.lang.Exception
import java.security.Key
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

/**
 * Created by leidong on 2017/5/9.
 */
object AESUtils2 {
    /**
     * 密钥算法
     */
    const val KEY_ALGORITHM = "AES"

    /**
     * 加密/解密算法  /工作模式  /填充方式
     */
    const val CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding"

    /**
     * 转换密钥
     * @param key 待密钥
     * @return 转换后的密钥
     * @throws Exception 抛出异常
     */
    @Throws(Exception::class)
    private fun toKey(key: ByteArray): Key {
        //实例化AES密钥材料
        return SecretKeySpec(key, KEY_ALGORITHM)
    }

    /**
     * AES解密
     * @param data 待解密数据
     * @param key 密钥
     * @return 明文
     * @throws Exception 抛出异常
     */
    @Throws(Exception::class)
    private fun decrypy(data: ByteArray, key: ByteArray): ByteArray {
        //还原密钥
        val k = toKey(key)
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
        //初始化，设置解密模式
        cipher.init(Cipher.DECRYPT_MODE, k)
        return cipher.doFinal(data)
    }

    /**
     * AES解密
     * @param data 密文
     * @param aesKey AES密钥
     * @return 明文
     * @throws Exception 抛出异常
     */
    @Throws(Exception::class)
    fun decrypt(data: String?, aesKey: String?): String {
        val data_byets = Base64.decode(data, Base64.DEFAULT)
        val aesKey_bytes = Base64.decode(aesKey, Base64.DEFAULT)
        val result = decrypy(data_byets, aesKey_bytes)
        return String(result)
    }

    /**
     * AES加密
     * @param data 待加密数据
     * @param key 密钥
     * @return 密文
     * @throws Exception 抛出异常
     */
    @Throws(Exception::class)
    private fun encrypy(data: ByteArray, key: ByteArray): ByteArray {
        val k = toKey(key)
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
        //初始化，设置解密模式
        cipher.init(Cipher.ENCRYPT_MODE, k)
        return cipher.doFinal(data)
    }

    /**
     * AES加密
     * @param data 待加密数据
     * @param aesKey AES密钥
     * @return 密文
     * @throws Exception 抛出异常
     */
    @Throws(Exception::class)
    fun encrypt(data: String, aesKey: String?): String {
        val data_bytes = data.toByteArray()
        val aesKey_bytes = Base64.decode(aesKey, Base64.DEFAULT)
        val result = encrypy(data_bytes, aesKey_bytes)
        return Base64.encodeToString(result, Base64.DEFAULT)
    }

    /**
     * 生成AES密钥
     * @return AES密钥
     * @throws Exception 抛出异常
     */
    @Throws(Exception::class)
    fun initKey(): String {
        //实例化
        val keyGenerator =
            KeyGenerator.getInstance(KEY_ALGORITHM)
        //设置密钥长度
        keyGenerator.init(256)
        //生成密钥
        val secretKey = keyGenerator.generateKey()
        //获得密钥的二进制编码形式
        val aesKey_bytes = secretKey.encoded
        return Base64.encodeToString(aesKey_bytes, Base64.DEFAULT)
    }
}