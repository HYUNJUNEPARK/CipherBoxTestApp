package com.june.strongboxkey.util

import android.util.Base64
import com.june.strongboxkey.Constants.CURVE_TYPE
import com.june.strongboxkey.Constants.KEY_AGREEMENT_ALGORITHM
import com.june.strongboxkey.Constants.KEY_ALGORITHM
import com.june.strongboxkey.Constants.KEY_GEN_ALGORITHM
import com.june.strongboxkey.model.KeyPairModel
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement
import javax.crypto.spec.SecretKeySpec

class KeyProvider {
    fun keyPair(): KeyPairModel {
        val keyPairGenerator = KeyPairGenerator.getInstance(KEY_GEN_ALGORITHM) //EC
        keyPairGenerator.initialize(ECGenParameterSpec(CURVE_TYPE)) //secp256r1
        val keyPair = keyPairGenerator.generateKeyPair()
        return KeyPairModel(keyPair.private, keyPair.public)
    }

    fun sharedSecretKey(senderPrivateKey: PrivateKey, recipientPublicKey: PublicKey): String {
        val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM) //ECDH
        keyAgreement.init(senderPrivateKey)
        keyAgreement.doPhase(recipientPublicKey, true)
        val _sharedSecretKey: ByteArray = keyAgreement.generateSecret()
        val sharedSecretKey:String = Base64.encodeToString(_sharedSecretKey, Base64.DEFAULT)
        return sharedSecretKey
    }

    fun sharedSecretKey__(senderPrivateKey: PrivateKey, recipientPublicKey: PublicKey): ByteArray {
        val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM) //ECDH
        keyAgreement.init(senderPrivateKey)
        keyAgreement.doPhase(recipientPublicKey, true)
        val _sharedSecretKey: ByteArray = keyAgreement.generateSecret()
        //val sharedSecretKey:String = Base64.encodeToString(_sharedSecretKey, Base64.DEFAULT)
        return _sharedSecretKey
    }


    //https://developer.android.com/reference/java/security/MessageDigest
    //update : 해시할 데이터를 추가 (ssk / random)
    //digest : 최종 데이터로 해시를 생성 마지막에 호출됨
    //HMAC SHA 256 //
    //TODO 해시를 만드는 작업이 필요하고 랜덤넘버를 더해

    fun byteArrayToKey(sharedSecretKey : ByteArray): Key {
        return SecretKeySpec(sharedSecretKey, KEY_ALGORITHM)
    }
}