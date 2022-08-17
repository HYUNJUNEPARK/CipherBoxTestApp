package com.june.strongboxkey.app

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.june.strongboxkey.R
import com.june.strongboxkey.app.TestStrongBox.Companion.defaultKeyStore
import com.june.strongboxkey.app.TestStrongBox.Companion.filePassword
import com.june.strongboxkey.app.TestStrongBox.Companion.keystoreFile
import com.june.strongboxkey.databinding.ActivityMainBinding
import com.june.strongboxkey.strongbox.StrongBox
import java.io.FileInputStream
import java.security.PublicKey

class MainActivity : AppCompatActivity() {
    private val binding by lazy { ActivityMainBinding.inflate(layoutInflater) }

    //test
    //random, ec key pair, ssk keystore
    private val strongBox = TestStrongBox.getInstance(this)
    private var random: String? = null

    //sdk
    //public key provider
    private val publicKeyProviderStrongBox = StrongBox.getInstance(this)
    private var publicKey: PublicKey? = null

    //shared preference
    private lateinit var spm: SharedPreferenceManager

    private var keyId: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(binding.root)

        spm = SharedPreferenceManager.getInstance(this)!!
        initKeyState()
    }

    fun keyGenButtonClicked(v: View) {
        strongBox.generateECKeyPair()
        random = strongBox.generateRandom(32)
        publicKeyProviderStrongBox.generateECKeyPair()
        publicKey = publicKeyProviderStrongBox.getECPublicKey()

        if (strongBox.getECPublicKey() != null) {
            binding.strongBoxKeyStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
        }
        if (random != null) {
            binding.randomNumberStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
        }
        if (publicKey != null) {
            binding.publicKeyProviderKeyStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
        }

        Log.d("testLog", "random : $random")
    }


    private fun initKeyState() {

    }

    fun sharedSecretKeyGenButtonClicked(v: View) {
        if (publicKey == null || random == null) {
            Toast.makeText(this, "퍼블릭키 또는 랜덤 없음", Toast.LENGTH_SHORT).show()
            return
        }

        strongBox.generateSharedSecretKey(publicKey!!, random!!).let { result ->
            keyId = result
        }
        Log.d("testLog", "ssk Key Id : $keyId")
        if (keyId != null) {
            binding.sharedSecretKeyStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
        }
    }



    fun strongBoxKeyDeleteButtonClicked(v: View) {
        strongBox.deleteECKeyPair().let { result ->
            if (result) {
                random = null
                binding.strongBoxKeyStateImageView.setImageResource(R.drawable.ic_baseline_cancel_24)
                binding.randomNumberStateImageView.setImageResource(R.drawable.ic_baseline_cancel_24)
            } else {
                Toast.makeText(this, "키 삭제 안됨", Toast.LENGTH_SHORT).show()
            }
        }
    }

    fun publicKeyProviderKeyDeleteButtonClicked(v: View) {
        publicKeyProviderStrongBox.deleteECKeyPair().let { result ->
            if (result) {
                binding.publicKeyProviderKeyStateImageView.setImageResource(R.drawable.ic_baseline_cancel_24)
                publicKey = null
            } else {
                Toast.makeText(this, "키 삭제 안됨", Toast.LENGTH_SHORT).show()
            }
        }
    }



    fun sharedSecretKeyDeleteButtonClicked(v: View) {
        if (random == null) return

        strongBox.deleteSharedSecretKey(random!!)

    }

    fun messageSendButtonClicked(v: View) = with(binding) {
        if (random == null) return@with

        try {
            val fis: FileInputStream? = openFileInput(keystoreFile)
            defaultKeyStore.load(fis, filePassword)
            fis?.close()

            if (!defaultKeyStore.containsAlias(random)) {
                Toast.makeText(this@MainActivity, "shared secret key 없음", Toast.LENGTH_SHORT).show()
                return@with
            }
        }
        catch (e: Exception) {
            e.printStackTrace()
        }

        val userInput = messageEditText.text.toString()
        userMessageTextView.text = userInput
        val encryption = strongBox.encrypt(userInput, random!!)
        encryptionCBCTextView.text = encryption
        val decryption = strongBox.decrypt(encryption, random!!)
        decryptionCBCTextView.text = decryption

        messageEditText.text = null
    }

}