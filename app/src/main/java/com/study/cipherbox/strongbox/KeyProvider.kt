package com.study.cipherbox.strongbox

import android.security.keystore.KeyProperties
import com.study.cipherbox.app.KeyPairModel
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement

class KeyProvider {
    companion object {
        const val CURVE_TYPE = "secp256r1"
        const val ENCRYPTION_PADDING_PKCS7 = "AES/CBC/PKCS7Padding"
        const val ECDH_ALGORITHM = "ECDH"
    }

    fun generateECKeypair(): KeyPairModel {
        val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC) //EC
        keyPairGenerator.initialize(ECGenParameterSpec(CURVE_TYPE)) //secp256r1
        val keyPair = keyPairGenerator.generateKeyPair()
        return KeyPairModel(keyPair.private, keyPair.public)
    }

    fun agreementKey(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val keyAgreement = KeyAgreement.getInstance(ECDH_ALGORITHM)
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKey, true)
        val sharedSecretKey: ByteArray = keyAgreement.generateSecret()
        return hashSHA256(sharedSecretKey)
    }

    private fun hashSHA256(key: ByteArray): ByteArray {
        val hash: ByteArray
        try {
            val messageDigest = MessageDigest.getInstance(KeyProperties.DIGEST_SHA256)
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