package com.june.strongboxkey.app

import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.june.strongboxkey.databinding.ActivityMainBinding
import com.june.strongboxkey.strongbox.KeyProvider
import java.security.PublicKey

class MainActivity : AppCompatActivity() {
    private val binding by lazy { ActivityMainBinding.inflate(layoutInflater) }
    private var sharedSecretHash: ByteArray? = null
//    private var keyPairA: KeyPairModel? = null
//    private var keyPairB: KeyPairModel? = null

    private lateinit var publicKey: PublicKey
    private val keyProvider = KeyProvider(this)
    private val libTest = LibTest()
    private var nonce: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(binding.root)
    }

    fun keyGenButtonClicked(v: View) {
        libTest.generateECKeyPair()
        keyProvider.generateECKeyPair()

        nonce = keyProvider.generateRandom(32)

        //상대방의 퍼블릭키
        publicKey = libTest.getECPublicKey()!!

        //shared secret key 생성
        keyProvider.generateSharedSecretKey(publicKey, nonce!!)

        //상대방 퍼블릭키 가져와서 확인
        if (libTest.getECPublicKey() != null) {
            Toast.makeText(this, "상대방 퍼블릭키를 가져올 수 있음", Toast.LENGTH_SHORT).show()
        }





        //sharedSecretHash = keyProvider.generateSharedSecretKey(publicKey, random)
//        if (keyPairA != null && keyPairB != null) {
//
//
////            sharedSecretHash = keyProvider.generateSharedSecretKey(
////                keyPairB!!.publicKey,
////                keyProvider.getRandom()
////            )
//
//
//
//        }
//        else {
//            Toast.makeText(this, "Shared Secret Key 생성 실패", Toast.LENGTH_SHORT).show()
//        }
        initKeyPairView()
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
        val userInput = messageEditText.text.toString()
        userMessageTextView.text = userInput

        val encryption = keyProvider.encrypt(userInput, nonce!!)
        encryptionCBCTextView.text = encryption



//        val encryptionCBC = AESCiper().encryptMessage(userInput, sharedSecretHash!!)
//        encryptionCBCTextView.text = encryptionCBC
//
//
//        val decryptionCBC = AESCiper().decryptMessage(encryptionCBC, sharedSecretHash!!)
//        decryptionCBCTextView.text = decryptionCBC


        messageEditText.text = null
    }

    private fun initKeyPairView() {

//        if (keyPairA?.privateKey != null) binding.privateKeyAText.visibility = View.VISIBLE
//            else binding.privateKeyAText.visibility = View.INVISIBLE
//        if (keyPairA?.publicKey != null) binding.publicKeyAText.visibility = View.VISIBLE
//            else binding.publicKeyAText.visibility = View.INVISIBLE
//        if (keyPairB?.privateKey != null) binding.privateKeyBText.visibility = View.VISIBLE
//            else binding.privateKeyBText.visibility = View.INVISIBLE
//        if (keyPairB?.publicKey != null) binding.publicKeyBText.visibility = View.VISIBLE
//            else binding.publicKeyBText.visibility = View.INVISIBLE

    }


//    fun test1ButtonClicked(v: View) {
//        Toast.makeText(this, "1111", Toast.LENGTH_SHORT).show()
//
//        val key: Key = SecretKeySpec(
//            sharedSecretHash,
//            KeyProperties.KEY_ALGORITHM_AES
//        )
//        StoreInFile(this).storeKeystoreInFile( "key2", key)
//    }
//
//
//
//    fun test2ButtonClicked(v: View) {
//        println(StoreInFile(this).readAllKeysInFile())
//    }

}