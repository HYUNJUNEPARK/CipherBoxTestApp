package com.june.strongboxkey.activity

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.databinding.DataBindingUtil
import com.june.strongboxkey.R
import com.june.strongboxkey.databinding.ActivityMainBinding
import com.june.strongboxkey.model.KeyPairModel
import com.june.strongboxkey.util.AESUtils
import com.june.strongboxkey.util.KeyProvider

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private var keyPairA: KeyPairModel? = null
    private var keyPairB: KeyPairModel? = null
    private var sharedSecretKey: ByteArray? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = DataBindingUtil.setContentView(this, R.layout.activity_main)

        binding.mainActivity = this
    }

    fun keyGen() {
        keyPairA = KeyProvider().keyPair() //sender
        keyPairB = KeyProvider().keyPair() //recipient

        if (keyPairA != null && keyPairB != null) {
            sharedSecretKey = KeyProvider().sharedSecretKey(keyPairA!!.privateKey, keyPairB!!.publicKey)
        }
        else {
            Toast.makeText(this, "Shared Secret Key 생성 실패", Toast.LENGTH_SHORT).show()
        }
        initKeyPairView()

        //TODO
//        val encryption = AESUtils().encryption("user Input", sharedSecretKey)
//        val decryption = AESUtils().decryption(encryption, sharedSecretKey)
//        Log.d("testLog", "DECRYPTION: $decryption")
    }

    private fun initKeyPairView() {
        if (keyPairA?.privateKey != null) binding.privateKeyAText.visibility = View.VISIBLE else binding.privateKeyAText.visibility = View.INVISIBLE
        if (keyPairA?.publicKey != null) binding.publicKeyAText.visibility = View.VISIBLE else binding.publicKeyAText.visibility = View.INVISIBLE
        if (keyPairB?.privateKey != null) binding.privateKeyBText.visibility = View.VISIBLE else binding.privateKeyBText.visibility = View.INVISIBLE
        if (keyPairB?.publicKey != null) binding.publicKeyBText.visibility = View.VISIBLE else binding.publicKeyBText.visibility = View.INVISIBLE
    }
}