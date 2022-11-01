package com.study.cipherbox.vm

import android.content.Context
import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.study.cipherbox.sdk.CipherBox
import com.study.cipherbox.sdk.ECKeyUtil
import com.study.cipherbox.sdk.EncryptedSharedPreferencesManager

class KeyViewModel: ViewModel() {
    val publicKey: LiveData<String>
        get() = _publicKey
    private var _publicKey = MutableLiveData<String>()

    val espKeyList: LiveData<String?>
        get() = _espKeyList
    private var _espKeyList = MutableLiveData<String?>()

    fun getPublicKey() {
        try {
            val cipherBox = CipherBox()
            _publicKey.value = ECKeyUtil.publicKeyToString(
                publicKey = cipherBox.getECPublicKey()
            )
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
        //_publicKey.value = null
    }
}