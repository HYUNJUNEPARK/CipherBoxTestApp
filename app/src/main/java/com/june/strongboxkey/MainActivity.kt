package com.june.strongboxkey

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import com.june.strongboxkey.util.Decryption
import com.june.strongboxkey.util.Encryption
import com.june.strongboxkey.util.KeyProvider

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val keyPairA = KeyProvider().keyPair() //sender
        val keyPairB = KeyProvider().keyPair() //recipient


//        val sharedSecretKey: String = KeyProvider().sharedSecretKey(keyPairA.privateKey, keyPairB.publicKey)
//        val encryption = Encryption().encryption("user Input", sharedSecretKey)
//        val decryption = Decryption().decryption(encryption, sharedSecretKey)
//        Log.d("testLog", "DECRYPTION: $decryption")
//
        val sharedSecretKey_: ByteArray = KeyProvider().sharedSecretKey__(keyPairA.privateKey, keyPairB.publicKey)
        val encryption__ = Encryption().encryption__("user Input", sharedSecretKey_)
        val decryption__ = Decryption().decryption__(encryption__, sharedSecretKey_)

        Log.d("testLog", "onCreate11111: $decryption__")



    }
}