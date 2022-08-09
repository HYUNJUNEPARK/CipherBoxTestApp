package com.june.strongboxkey.activity

import android.os.Bundle
import android.security.keystore.KeyProperties
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.june.strongboxkey.databinding.ActivityMainBinding
import com.june.strongboxkey.strongBox.KeyProvider
import com.june.strongboxkey.strongBox.StrongBoxConstants.TAG
import com.june.strongboxkey.strongBox.aes.AESDecryption
import com.june.strongboxkey.strongBox.aes.AESEncryption
import com.june.strongboxkey.strongBox.keystore.StoreInFile
import com.june.strongboxkey.strongBox.model.KeyPairModel
import java.security.Key
import java.security.KeyStore
import javax.crypto.spec.SecretKeySpec

class MainActivity : AppCompatActivity() {
    private val binding by lazy { ActivityMainBinding.inflate(layoutInflater) }
    private var sharedSecretHash: ByteArray? = null
    private var keyPairA: KeyPairModel? = null
    private var keyPairB: KeyPairModel? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(binding.root)

        Log.d(TAG, "onCreate: ${KeyStore.getDefaultType()}")
//        StoreFile(this).isKeyStoreFile("KeyStore1", "key1")
//        StoreFile(this).isKeyStoreFile("KeyStore1", "key2")
    }

    fun keyGenButtonClicked(v: View) {
        keyPairA = KeyProvider().createKeyPair() //sender
        keyPairB = KeyProvider().createKeyPair() //recipient

        if (keyPairA != null && keyPairB != null) {
            sharedSecretHash = KeyProvider().createSharedSecretHash(
                keyPairA!!.privateKey,
                keyPairB!!.publicKey,
                KeyProvider().getRandomNumbers()
            )
        }
        else {
            Toast.makeText(this, "Shared Secret Key 생성 실패", Toast.LENGTH_SHORT).show()
        }
        initKeyPairView()
    }

    fun messageSendButtonClicked(v: View) = with(binding) {
        if (keyPairA == null || keyPairB == null || sharedSecretHash == null) {
            Toast.makeText(this@MainActivity, "암복호화 키 필요", Toast.LENGTH_SHORT).show()
            return@with
        }
        val userInput = messageEditText.text.toString()
        userMessageTextView.text = userInput
        val encryptionCBC = AESEncryption().encryptionCBCMode(userInput, sharedSecretHash!!)
        encryptionCBCTextView.text = encryptionCBC
        val decryptionCBC = AESDecryption().decryptionCBCMode(encryptionCBC, sharedSecretHash!!)
        decryptionCBCTextView.text = decryptionCBC
        messageEditText.text = null
    }

    private fun initKeyPairView() {
        if (keyPairA?.privateKey != null) binding.privateKeyAText.visibility = View.VISIBLE
            else binding.privateKeyAText.visibility = View.INVISIBLE
        if (keyPairA?.publicKey != null) binding.publicKeyAText.visibility = View.VISIBLE
            else binding.publicKeyAText.visibility = View.INVISIBLE
        if (keyPairB?.privateKey != null) binding.privateKeyBText.visibility = View.VISIBLE
            else binding.privateKeyBText.visibility = View.INVISIBLE
        if (keyPairB?.publicKey != null) binding.publicKeyBText.visibility = View.VISIBLE
            else binding.publicKeyBText.visibility = View.INVISIBLE
    }




    fun test1ButtonClicked(v: View) {
        Toast.makeText(this, "1111", Toast.LENGTH_SHORT).show()

        val key: Key = SecretKeySpec(
            sharedSecretHash,
            KeyProperties.KEY_ALGORITHM_AES
        )

        StoreInFile(this).storeKeystoreInFile( "key1", key)

    }



    fun test2ButtonClicked(v: View) {
//        StoreInFile(this).isKeyStoreFile("KeyStore1", "key1")
//        StoreInFile(this).isKeyStoreFile("KeyStore1", "key2")

        StoreInFile(this).readAllKeysInFile()
//        StoreInFile(this).readAllKeysInFile("KeyStore2")
    }




}