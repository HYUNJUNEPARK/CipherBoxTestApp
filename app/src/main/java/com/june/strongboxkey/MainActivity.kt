package com.june.strongboxkey

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Base64
import android.util.Log
import com.june.strongboxkey.util.AESUtils
import com.june.strongboxkey.util.KeyProvider

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val keyPairA = KeyProvider().keyPair() //sender
        val keyPairB = KeyProvider().keyPair() //recipient

        val sharedSecretKey_byte = KeyProvider().sharedSecretKey(keyPairA.privateKey, keyPairB.publicKey)
        Log.d("testLog", "shared secret key: $sharedSecretKey_byte")

        val sharedSecretKey_str = Base64.encodeToString(sharedSecretKey_byte, Base64.DEFAULT)






        val encryption = AESUtils.encrypt("aaabbbccc", sharedSecretKey_str)
        Log.d("testLog", "ENCRYPTION: $encryption")

        val decryption = AESUtils.decrypt(encryption, sharedSecretKey_str)
        Log.d("testLog", "DECRYPTION: $decryption")
    }
}