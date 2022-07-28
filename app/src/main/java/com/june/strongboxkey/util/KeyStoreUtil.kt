package com.june.strongboxkey.util

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.june.strongboxkey.constant.Constants
import com.june.strongboxkey.model.KeyPairModel
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec

class KeyStoreUtil {
    private val keyStore = KeyStore.getInstance(Constants.KEYSTORE_TYPE).apply {
        load(null)
    }

    fun updateKeyPairToKeyStore() {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            Constants.KEY_GEN_ALGORITHM,
            Constants.KEYSTORE_TYPE
        )
        val parameterSpec = KeyGenParameterSpec.Builder(
            Constants.KEYSTORE_MY_KEYPAIR_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).run {
            setUserAuthenticationRequired(false)
            ECGenParameterSpec(Constants.CURVE_TYPE) //secp256r1
            build()
        }
        keyPairGenerator.initialize(parameterSpec)
        keyPairGenerator.generateKeyPair()
    }

    fun getKeyPairFromKeyStore(): KeyPairModel {
        val keyStoreEntry = keyStore.getEntry(Constants.KEYSTORE_MY_KEYPAIR_ALIAS, null)
        val privateKey = (keyStoreEntry as KeyStore.PrivateKeyEntry).privateKey
        val publicKey = keyStore.getCertificate(Constants.KEYSTORE_MY_KEYPAIR_ALIAS).publicKey
        return KeyPairModel(privateKey, publicKey)
    }

    fun deleteKeyStoreKeyPair() {
        keyStore.deleteEntry(Constants.KEYSTORE_MY_KEYPAIR_ALIAS)
    }
}