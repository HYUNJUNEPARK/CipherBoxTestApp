package com.june.strongboxkey.activity

import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.june.strongboxkey.databinding.ActivityMainBinding
import com.june.strongboxkey.model.KeyPairModel
import com.june.strongboxkey.util.AESUtils
import com.june.strongboxkey.util.KeyProvider
import java.util.*

class MainActivity : AppCompatActivity() {
    private val binding by lazy { ActivityMainBinding.inflate(layoutInflater) }
    private var keyPairA: KeyPairModel? = null
    private var keyPairB: KeyPairModel? = null
    private var sharedSecretKey: ByteArray? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(binding.root)
    }

    fun keyGenButtonClicked(v: View) {
        keyPairA = KeyProvider().keyPair() //sender
        keyPairB = KeyProvider().keyPair() //recipient

        if (keyPairA != null && keyPairB != null) {
            sharedSecretKey = KeyProvider().sharedSecretKey(keyPairA!!.privateKey, keyPairB!!.publicKey)
        }
        else {
            Toast.makeText(this, "Shared Secret Key 생성 실패", Toast.LENGTH_SHORT).show()
        }
        initKeyPairView()
    }

    private fun initKeyPairView() {
        if (keyPairA?.privateKey != null) binding.privateKeyAText.visibility = View.VISIBLE else binding.privateKeyAText.visibility = View.INVISIBLE
        if (keyPairA?.publicKey != null) binding.publicKeyAText.visibility = View.VISIBLE else binding.publicKeyAText.visibility = View.INVISIBLE
        if (keyPairB?.privateKey != null) binding.privateKeyBText.visibility = View.VISIBLE else binding.privateKeyBText.visibility = View.INVISIBLE
        if (keyPairB?.publicKey != null) binding.publicKeyBText.visibility = View.VISIBLE else binding.publicKeyBText.visibility = View.INVISIBLE
    }

    fun messageSendButtonClicked(v: View) = with(binding) {
        if (keyPairA == null || keyPairB == null || sharedSecretKey == null) {
            Toast.makeText(this@MainActivity, "암복호화 키 필요", Toast.LENGTH_SHORT).show()
            return@with
        }
        val userInput = messageEditText.text.toString()
        userMessageTextView.text = userInput

        val encryption = AESUtils().encryption(userInput, sharedSecretKey!!)
        binding.encryptionTextView.text = encryption

//        binding.encryptionTextView.text = String(encryption) //TODO


        val decryption = AESUtils().decryption(encryption, sharedSecretKey!!)
        binding.decryptionTextView.text = decryption

        messageEditText.text = null
    }
}