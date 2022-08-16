package com.june.strongboxkey.app

import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.june.strongboxkey.R
import com.june.strongboxkey.databinding.ActivityMainBinding
import com.june.strongboxkey.strongbox.StrongBox
import java.io.FileInputStream
import java.security.KeyStore
import java.security.PublicKey

class MainActivity : AppCompatActivity() {
    private val binding by lazy { ActivityMainBinding.inflate(layoutInflater) }
    //sdk
    private val sdkUserStrongBox = StrongBox.getInstance(this)
    private val sdkUserKeyStoreAlias = "androidKeyStoreKey"
    private var random: String? = null

    //test
    private val testUserStrongBox = StrongBoxTest.getInstance(this)
    private val testUserKeyStoreAlias = "test_androidKeyStoreKey"
    private var publicKey: PublicKey ?= null

    //shared Secret Key
    private val keystoreFile = "default_keystore"
    private val storePassword = "defaultStorePassword".toCharArray()
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(binding.root)
        initKeyState()
    }

    private fun initKeyState()= with(binding) {
        val androidKeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }

        val defaultKeyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            var fis: FileInputStream? = null
            try {
                fis = openFileInput(keystoreFile)
            }
            catch (e: Exception){
                load(null)
            }
            load(fis, storePassword)
        }

        //sdk
        if (androidKeyStore.containsAlias(sdkUserKeyStoreAlias)) {
            sdkUserKeyStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
//            if (sp!!.getString(spKey, "null") != "null") {
//                random = sp!!.getString(spKey, "null")
//            }
//            else {
//                Toast.makeText(this@MainActivity, "랜덤을 가져올 수 없음", Toast.LENGTH_SHORT).show()
//            }
        }

        //test
        if (androidKeyStore.containsAlias(testUserKeyStoreAlias)) {
            testUserKeyStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
            publicKey = testUserStrongBox.getECPublicKey()
        }

        //shared secret key
        try {
            val fis: FileInputStream? = openFileInput(keystoreFile)
            defaultKeyStore.load(fis, storePassword)
            fis?.close()
        }
        catch (e: Exception) {
            return@with
        }
        if (defaultKeyStore.containsAlias(random)) {
            sharedSecretKeyStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
        }
    }

    //TODO sp random number
    fun keyGenButtonClicked(v: View) {
        //sdk
        sdkUserStrongBox.generateECKeyPair()
        random = sdkUserStrongBox.generateRandom(32)


        //test
        testUserStrongBox.generateECKeyPair()

        initKeyState()
    }

    fun sdkKeyDeleteButtonClicked(v: View) {
        sdkUserStrongBox.deleteECKeyPair().let { result ->
            if (result) {
                Toast.makeText(this, "SDK 키 삭제", Toast.LENGTH_SHORT).show()
                binding.sdkUserKeyStateImageView.setImageResource(R.drawable.ic_baseline_cancel_24)
            }
            else {
                Toast.makeText(this, "SDK 키 삭제 실패", Toast.LENGTH_SHORT).show()
            }
        }
    }

    fun testKeyDeleteButtonClicked(v: View) {
        testUserStrongBox.deleteECKeyPair().let { result ->
            if (result) {
                Toast.makeText(this, "TEST 키 삭제", Toast.LENGTH_SHORT).show()
                binding.testUserKeyStateImageView.setImageResource(R.drawable.ic_baseline_cancel_24)
            }
            else {
                Toast.makeText(this, "TEST 키 삭제 실패", Toast.LENGTH_SHORT).show()
            }
        }
    }

    fun sharedSecretKeyGenButtonClicked(v: View) {
        Toast.makeText(this, "공유키 생성", Toast.LENGTH_SHORT).show()
    }

    fun sharedSecretKeyDeleteButtonClicked(v: View) {
        Toast.makeText(this, "공유키 삭제", Toast.LENGTH_SHORT).show()
    }

    fun messageSendButtonClicked(v: View) = with(binding) {
//        if (publicKey != null) {
//            Log.d("testLog", "public Key set up")
//        }
//
//        if (sharedSecretHash != null) {
//            Log.d("testLog", "shared SecretKey set up")
//        }

//        if (keyPairA == null || keyPairB == null || sharedSecretHash == null) {
//            Toast.makeText(this@MainActivity, "암복호화 키 필요", Toast.LENGTH_SHORT).show()
//            return@with
//        }
//        val userInput = messageEditText.text.toString()
//        userMessageTextView.text = userInput
//
//        val encryption = strongBox.encrypt(userInput, nonce!!)
//        encryptionCBCTextView.text = encryption
//
//        val decryption = strongBox.decrypt(encryption, nonce!!)
//        decryptionCBCTextView.text = decryption

//        val encryptionCBC = AESCiper().encryptMessage(userInput, sharedSecretHash!!)
//        encryptionCBCTextView.text = encryptionCBC
//
//
//        val decryptionCBC = AESCiper().decryptMessage(encryptionCBC, sharedSecretHash!!)
//        decryptionCBCTextView.text = decryptionCBC


        messageEditText.text = null
    }
}