package com.june.strongboxkey.util

import com.june.strongboxkey.constant.Constants.CURVE_TYPE
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

    fun sharedSecretKeyHash(senderPrivateKey: PrivateKey, recipientPublicKey: PublicKey): ByteArray {
        val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM) //ECDH
        keyAgreement.init(senderPrivateKey)
        keyAgreement.doPhase(recipientPublicKey, true)
        val sharedSecretKey: ByteArray = keyAgreement.generateSecret()
        val hash = hashSHA256(sharedSecretKey)
        return hash
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
}