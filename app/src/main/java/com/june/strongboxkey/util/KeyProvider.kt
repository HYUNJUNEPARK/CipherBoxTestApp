package com.june.strongboxkey.util

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.june.strongboxkey.constant.Constants.CURVE_TYPE
import com.june.strongboxkey.constant.Constants.KEYSTORE_MY_KEYPAIR_ALIAS
import com.june.strongboxkey.constant.Constants.KEYSTORE_SECRET_KEY_ALIAS
import com.june.strongboxkey.constant.Constants.KEYSTORE_TYPE
import com.june.strongboxkey.constant.Constants.KEY_AGREEMENT_ALGORITHM
import com.june.strongboxkey.constant.Constants.KEY_GEN_ALGORITHM
import com.june.strongboxkey.constant.Constants.MESSAGE_DIGEST_ALGORITHM
import com.june.strongboxkey.model.KeyPairModel
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement

class KeyProvider {
    fun keyPair(): KeyPairModel {
        val keyPairGenerator = KeyPairGenerator.getInstance(KEY_GEN_ALGORITHM) //EC
        keyPairGenerator.initialize(ECGenParameterSpec(CURVE_TYPE)) //secp256r1
        val keyPair = keyPairGenerator.generateKeyPair()
        return KeyPairModel(keyPair.private, keyPair.public)
    }

    fun sharedSecretHash(myPrivateKey: PrivateKey, counterpartPublicKey: PublicKey): ByteArray {
        val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM) //ECDH
        keyAgreement.init(myPrivateKey)
        keyAgreement.doPhase(counterpartPublicKey, true)
        val sharedSecret: ByteArray = keyAgreement.generateSecret()
        val sharedSecretHash = hashSHA256(sharedSecret)
        return sharedSecretHash
    }

    private fun hashSHA256(key: ByteArray): ByteArray {
        val hash: ByteArray
        try {
            val messageDigest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM) //SHA-256
            messageDigest.update(key)
            hash = messageDigest.digest(randomByteArrayGenerator())
        }
        catch (e: CloneNotSupportedException) {
            throw DigestException("$e")
        }
        return hash
    }

    private fun randomByteArrayGenerator(): ByteArray {
        val randomByteArray = ByteArray(32)
        SecureRandom().nextBytes(randomByteArray)
        return randomByteArray
    }

//KeyStore
    private val keyStore = KeyStore.getInstance(KEYSTORE_TYPE).apply {
        load(null)
    }

    fun updateKeyPairToKeyStore() {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KEY_GEN_ALGORITHM,
            KEYSTORE_TYPE
        )
        val parameterSpec = KeyGenParameterSpec.Builder(
            KEYSTORE_MY_KEYPAIR_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).run {
            setUserAuthenticationRequired(false)
            ECGenParameterSpec(CURVE_TYPE) //secp256r1
            build()
        }
        keyPairGenerator.initialize(parameterSpec) 
        keyPairGenerator.generateKeyPair()
    }

    fun keyStoreKeyPair(): KeyPairModel? {
        val keyStoreEntry = keyStore.getEntry(KEYSTORE_MY_KEYPAIR_ALIAS, null)
        val privateKey = (keyStoreEntry as KeyStore.PrivateKeyEntry).privateKey
        val publicKey = keyStore.getCertificate(KEYSTORE_MY_KEYPAIR_ALIAS).publicKey
        return KeyPairModel(privateKey, publicKey)
    }

    fun deleteKeyStoreKeyPair() {
        keyStore.deleteEntry(KEYSTORE_MY_KEYPAIR_ALIAS)
    }
}