package com.study.cipher

import androidx.lifecycle.ViewModel

class AesSdkViewModel(): ViewModel() {
    private val aesCipherSdk = AesCipher.getInstance()

    fun encrypt(message: String): String? {
        return aesCipherSdk.encrypt(message)
    }

    fun decrypt(message: String): String? {
        return aesCipherSdk.decrypt(message)
    }
}