package com.study.cipher

import android.app.Application
import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.study.ecdhcipher.ESPManager
import com.study.ecdhcipher.EcdhCipher

class EcdhSdkViewModel(application: Application): AndroidViewModel(application) {
    private val context = getApplication<Application>().applicationContext
    private val ecdhCipherSdk = EcdhCipher.getInstance(context)!!

    val publicKey: LiveData<String?>
        get() = _publicKey
    private var _publicKey = MutableLiveData<String?>()

    val espKeyList: LiveData<String?>
        get() = _espKeyList
    private var _espKeyList = MutableLiveData<String?>()

    val currentSharedSecretKeyId: LiveData<String?>
        get() = _currentSharedSecretKeyId
    private var _currentSharedSecretKeyId = MutableLiveData<String?>()

    val isECKeyPair: LiveData<Boolean>
        get() = _isECKeyPair
    private var _isECKeyPair = MutableLiveData<Boolean>()

    val isSharedSecretKey: LiveData<Boolean>
        get() = _isSharedSecretKey
    private var _isSharedSecretKey = MutableLiveData<Boolean>()


    init {
        getPublicKey()
        getESPKeyIdList(context)
        isECKeyPairOnKeyStore().let { isECKeyPair ->
            _isECKeyPair.value = isECKeyPair
        }
    }

    @RequiresApi(Build.VERSION_CODES.S)
    fun generateECKeyPair(): Boolean {
        try {
            ecdhCipherSdk.generateECKeyPair()
            getPublicKey()
            _isECKeyPair.value = true
            return true
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return false
    }

    fun reset() {
        ecdhCipherSdk.reset()
        _isECKeyPair.value = false
        _espKeyList.value = null
        _publicKey.value = null
        _currentSharedSecretKeyId.value = null
    }

    fun encrypt(message: String): String? {
        if (currentSharedSecretKeyId.value == null) {
            //Error Log
            return null
        }
        return ecdhCipherSdk.encrypt(message, currentSharedSecretKeyId.value!!)
    }

    fun decrypt(message: String): String? {
        if (currentSharedSecretKeyId.value == null) {
            //Error Log
            return null
        }
        return ecdhCipherSdk.decrypt(message, currentSharedSecretKeyId.value!!)
    }

    fun generateSharedSecretKey() {
        try {
            //SharedSecreteKey 의 KeyId 와 생성 시 필요한 secureRandom
            generateRandom()

            ecdhCipherSdk.generateSharedSecretKey(
                publicKey = _publicKey.value!!,
                secureRandom = currentSharedSecretKeyId.value!!
            )

            _isSharedSecretKey.value = true
            getESPKeyIdList(context)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun getPublicKey() {
        try {
            val cipher = ecdhCipherSdk
            if (cipher.getECPublicKey() == null) {
                return
            }
            _publicKey.value = cipher.getECPublicKey()!!
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun getESPKeyIdList(context: Context) {
        try {
            val espm = ESPManager.getInstance(context)!!

            espm.getKeyIdList().let {
                    keyIdList ->
                val keyIds = StringBuffer("")
                for (keyId in keyIdList) {
                    keyIds.append("$keyId\n")
                }
                _espKeyList.value = keyIds.toString()
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun isECKeyPairOnKeyStore(): Boolean {
        try {
            return ecdhCipherSdk.isECKeyPairOnKeyStore()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return false
    }

    private fun generateRandom() {
        try {
            _currentSharedSecretKeyId.value = ecdhCipherSdk.generateRandom(32)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}