package com.june.strongboxkey.activity

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import com.june.strongboxkey.R
import com.june.strongboxkey.util.AESUtils
import com.june.strongboxkey.util.KeyProvider

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val keyPairA = KeyProvider().keyPair() //sender
        val keyPairB = KeyProvider().keyPair() //recipient

        val sharedSecretKey: ByteArray = KeyProvider().sharedSecretKey(keyPairA.privateKey, keyPairB.publicKey)
        val encryption = AESUtils().encryption("user Input", sharedSecretKey)
        val decryption = AESUtils().decryption(encryption, sharedSecretKey)
        Log.d("testLog", "DECRYPTION: $decryption")
    }
}