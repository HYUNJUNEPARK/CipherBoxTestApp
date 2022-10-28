package com.study.cipherbox.vm

import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.study.cipherbox.sdk.CipherBox
import com.study.cipherbox.sdk.ECKeyUtil

class KeyViewModel: ViewModel() {
    private val cipherBox = CipherBox()

    val publicKey: LiveData<String>
        get() = _publicKey
    private var _publicKey = MutableLiveData<String>()

    fun getPublicKey() {
        try {
            Log.d("testLog", "getPublicKey: 11111111111")
            _publicKey.value = ECKeyUtil.publicKeyToString(
                publicKey = cipherBox.getECPublicKey()
            )
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun reset() {
        _publicKey.value == null
    }
}