package com.june.strongboxkey

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Base64
import android.util.Log
import java.security.Key
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val keyPairA = KeyPairProvider().keyPair()
        val keyPairB = KeyPairProvider().keyPair()
        val counterpartPublicKey = keyPairB.publicKey //교환 받은 퍼플릭 키
        val keyAgreement = KeyAgreement.getInstance("ecdh")

        keyAgreement.init(keyPairA.privateKey)
        keyAgreement.doPhase(counterpartPublicKey, true)

//        //TODO byteArray not key
        val sharedSecretKey = keyAgreement.generateSecret()
        Log.d("testLog", "shared secret key: $sharedSecretKey")



        ///////
        val sharedSecretKey_str = Base64.encodeToString(sharedSecretKey, Base64.DEFAULT)

         val encryption = AESUtils.encrypt("aaabbbccc", sharedSecretKey_str)
        Log.d("testLog", "ENCRYPTION: $encryption")


        val decryption = AESUtils.decrypt(encryption, sharedSecretKey_str)
        Log.d("testLog", "DECRYPTION: $decryption")

//        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
//        cipher.init(Cipher.ENCRYPT_MODE, key)
//
//        Log.e("testLog", "onCreate: $cipher", )



//        //암호화
        //val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding") //
//        //shared Secret key -  ByteArray!
        //cipher.init(Cipher.ENCRYPT_MODE, sharedSecretKey)
//        val iv = cipher.iv // 복호화할 때나 암호화를 마무리할 때 사용
//        val encryption = cipher.doFinal()

    }
}