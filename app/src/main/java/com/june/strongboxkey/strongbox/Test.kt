package com.june.strongboxkey.strongbox

import android.security.keystore.KeyProperties
import com.june.strongboxkey.model.KeyPairModel
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec

class Test {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    fun createKeyPair(): KeyPairModel {
        val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC).apply {
            initialize(ECGenParameterSpec("secp256r1")) //curve type
        }
        val keyPair = keyPairGenerator.generateKeyPair()
        return KeyPairModel(keyPair.private, keyPair.public)
    }

    fun getKeyPairFromKeyStore(keyStoreAlias: String): KeyPairModel {
        val keyStoreEntry = keyStore.getEntry(keyStoreAlias, null)
        val privateKey = (keyStoreEntry as KeyStore.PrivateKeyEntry).privateKey
        val publicKey = keyStore.getCertificate(keyStoreAlias).publicKey
        return KeyPairModel(privateKey, publicKey)
    }
}