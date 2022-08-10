package com.june.strongboxkey.strongbox

import android.security.keystore.KeyProperties
import java.security.*
import javax.crypto.KeyAgreement

class KeyProvider {
    //TODO Error keyAgreement.init(myPrivateKey) -> USE Android 12, API 31 Device if not InvalidKeyException: Keystore operation failed
    fun generateSharedSecret(myPrivateKey: PrivateKey, partnerPublicKey: PublicKey, randomNumber: ByteArray): ByteArray {
        val sharedSecret: ByteArray

        try {
            KeyAgreement.getInstance("ECDH").apply {
                init(myPrivateKey)
                doPhase(partnerPublicKey, true)
            }.generateSecret().let { _sharedSecret ->
                val messageDigest = MessageDigest.getInstance(KeyProperties.DIGEST_SHA256).apply {
                    update(_sharedSecret)
                }
                sharedSecret = messageDigest.digest(randomNumber)
            }
        }
        //
        catch (e : Exception) {
            throw KeyException("$e")
        }
        catch (e: CloneNotSupportedException) {
            throw DigestException("$e")
        }
        return sharedSecret
    }


    //TODO 채널 메타 데이터로 올리려면 뺴두는게 편할 수도 ?
    fun getRandomNumbers(): ByteArray {
        val randomByteArray = ByteArray(32).apply {
            SecureRandom().nextBytes(this)
        }
        return randomByteArray
    }
}