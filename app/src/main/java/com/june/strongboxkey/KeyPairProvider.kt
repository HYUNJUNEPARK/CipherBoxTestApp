package com.june.strongboxkey

import android.util.Log
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

class KeyPairProvider {
    fun keyPair(): KeyPairModel {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair = keyPairGenerator.generateKeyPair()
        val publicKey = keyPair.public
        val privateKey = keyPair.private

        Log.d("testLog", "private : $privateKey \n public : $publicKey ")
        return KeyPairModel(privateKey, publicKey)
    }
}