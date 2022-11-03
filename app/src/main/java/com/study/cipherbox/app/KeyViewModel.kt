package com.study.cipherbox.app

import android.content.Context
import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.study.cipherbox.sdk.JavaUtil
import com.study.cipherbox.sdk.aos.CipherBox
import com.study.cipherbox.sdk.aos.ECKeyUtil
import com.study.cipherbox.sdk.aos.EncryptedSharedPreferencesManager

class KeyViewModel: ViewModel() {
    val publicKey: LiveData<String?>
        get() = _publicKey
    private var _publicKey = MutableLiveData<String?>()

    val espKeyList: LiveData<String?>
        get() = _espKeyList
    private var _espKeyList = MutableLiveData<String?>()

    fun getPublicKey() {
        try {
            val cipherBox = CipherBox()
            if (cipherBox.getECPublicKey() == null) {
                return
            }
            _publicKey.value = cipherBox.getECPublicKey()!!



            val publicKey = cipherBox.getECPublicKey()!!
            //val publicKey_str = ECKeyUtil.publicKeyToString(publicKey)
            //Log.d("testLog", "getPublicKey: $publicKey // $publicKey_str")
            //java.lang.IllegalArgumentException: Non-hexadecimal digit found: G
            //val publicKey_byte = JavaUtil.hexStringToByteArray(publicKey_str!!)
            //Log.d("testLog", "getPublicKey: $publicKey_byte")
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun getESPKeyIdList(context: Context) {
        try {
            val espm = EncryptedSharedPreferencesManager.getInstance(context)!!
            espm.getKeyIdList().let {
                    keyIdList ->
                val keyIds = StringBuffer("")
                for (keyId in keyIdList!!) {
                    keyIds.append("$keyId\n")
                }
                //_espKeyList.value = null
                _espKeyList.value = keyIds.toString()
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun reset() {
        _publicKey.value = null
    }
}