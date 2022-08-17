//package com.june.strongboxkey.tmporary
//
//import android.os.Bundle
//import android.util.Log
//import android.view.View
//import android.widget.Toast
//import androidx.appcompat.app.AppCompatActivity
//import com.june.strongboxkey.R
//import com.june.strongboxkey.app.SharedPreferenceManager
//import com.june.strongboxkey.app.TestStrongBox
//import com.june.strongboxkey.databinding.ActivityMainBinding
//import com.june.strongboxkey.strongbox.StrongBox
//import java.io.FileInputStream
//import java.security.KeyStore
//import java.security.PublicKey
//
//class DeprecatedMainActivity : AppCompatActivity() {
//    private val binding by lazy { ActivityMainBinding.inflate(layoutInflater) }
//    //sdk
//    private val sdkUserStrongBox = StrongBox.getInstance(this)
//    private val sdkUserKeyStoreAlias = "androidKeyStoreKey"
//    private val randomAlias = "randomNumber"
//    private var random: String? = null
//
//    //test
//    private val testUserStrongBox = TestStrongBox.getInstance(this)
//    private val testUserKeyStoreAlias = "test_androidKeyStoreKey"
//    private var publicKey: PublicKey ?= null
//
//    //shared Secret Key
//    private val keystoreFile = "keystore"
//    private val filePassword = "StorePassword".toCharArray()
//
//    //shared preference
//    private lateinit var spm: SharedPreferenceManager
//
////    private val defaultKeyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
////        var fis: FileInputStream? = null
////        try {
////            fis = openFileInput(keystoreFile)
////        }
////        catch (e: Exception){
////            load(null)
////            return@apply
////        }
////        load(fis, filePassword)
////    }
//
//    private val androidKeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
//        load(null)
//    }
//
//    override fun onCreate(savedInstanceState: Bundle?) {
//        super.onCreate(savedInstanceState)
//        setContentView(binding.root)
//
//        spm = SharedPreferenceManager.getInstance(this)!!
//        initKeyState()
//    }
//
//
//
//    private fun initKeyState()= with(binding) {
//        //sdk
//        if (androidKeyStore.containsAlias(sdkUserKeyStoreAlias)) {
//            sdkUserKeyStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
//            publicKey = sdkUserStrongBox.getECPublicKey()
//        }
//        //random
//        if (spm.getString(randomAlias, "null") != "null") {
//            RandomNumberStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
//            random = spm.getString(randomAlias, "null")
//        }
//        //test
//        if (androidKeyStore.containsAlias(testUserKeyStoreAlias)) {
//            testUserKeyStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
//        }
//
//        //shared secret key
////        try {
////            val fis: FileInputStream? = openFileInput(keystoreFile)
////            defaultKeyStore.load(fis, storePassword)
////            fis?.close()
////
////            if (defaultKeyStore.containsAlias(random)) {
////                sharedSecretKeyStateImageView.setImageResource(R.drawable.ic_baseline_check_circle_24)
////            }
////            else {
////                sharedSecretKeyStateImageView.setImageResource(R.drawable.ic_baseline_key_24)
////            }
////        }
////        catch (e: Exception) {
////            e.printStackTrace()
////        }
//    }
//
//    //TODO sp random number
//    fun keyGenButtonClicked(v: View) {
//        //sdk
//        sdkUserStrongBox.generateECKeyPair()
//        random = sdkUserStrongBox.generateRandom(32)
//        spm.putString(randomAlias, random)
//
//        //test
//        testUserStrongBox.generateECKeyPair()
//        Log.d("testLog", "random: $random")
//
//        initKeyState()
//    }
//
//    fun sdkKeyDeleteButtonClicked(v: View) {
//        sdkUserStrongBox.deleteECKeyPair().let { result ->
//            if (result) {
//                spm.putString(randomAlias, null)
//                Toast.makeText(this, "SDK 키 삭제", Toast.LENGTH_SHORT).show()
//                publicKey = null
//                binding.sdkUserKeyStateImageView.setImageResource(R.drawable.ic_baseline_cancel_24)
//                binding.RandomNumberStateImageView.setImageResource(R.drawable.ic_baseline_cancel_24)
//            }
//            else {
//                Toast.makeText(this, "SDK 키 삭제 실패", Toast.LENGTH_SHORT).show()
//            }
//        }
//    }
//
//    fun testKeyDeleteButtonClicked(v: View) {
//        testUserStrongBox.deleteECKeyPair().let { result ->
//            if (result) {
//                Toast.makeText(this, "TEST 키 삭제", Toast.LENGTH_SHORT).show()
//                binding.testUserKeyStateImageView.setImageResource(R.drawable.ic_baseline_cancel_24)
//            }
//            else {
//                Toast.makeText(this, "TEST 키 삭제 실패", Toast.LENGTH_SHORT).show()
//            }
//        }
//    }
//
//    fun sharedSecretKeyGenButtonClicked(v: View) {
//        if (publicKey == null || random == null) {
//            Toast.makeText(this, "Public Key 또는 Random 필요", Toast.LENGTH_SHORT).show()
//            return
//        }
//        testUserStrongBox.generateSharedSecretKey(publicKey!!, random!!).let { keyId ->
//            Toast.makeText(this, "공유키 생성", Toast.LENGTH_SHORT).show()
//            /*TODO
//                a. 채널을 초대한 사람이 해당 메서드를 사용할 때
//                -> keyId 를 채널의 메타데이터로 업로드하는 기능 구현이 필요
//                -> keyId 와 채널 URL 주소를 매핑해주는 로컬 DB 구현이 필요
//                b. 채널 초대받은 사람이 해당 메서드를 사용할 때
//                -> 채널 메타데이터로부터 데이터를 가져와 사용 파라미터로 nonce 로 사용
//                -> keyId 와 채널 URL 주소를 매핑해주는 로컬 DB 구현이 필요
//            */
//        }
//    }
//
//    fun sharedSecretKeyDeleteButtonClicked(v: View) {
//        if (random == null) return
//
//        //testDefaultKeyStore.deleteEntry(random!!)
////        testUserStrongBox.deleteSharedSecretKey(random!!).let { result ->
////            if (result) {
////                Toast.makeText(this, "공유키 삭제 성공", Toast.LENGTH_SHORT).show()
////            } else {
////                Toast.makeText(this, "공유키 삭제 실패", Toast.LENGTH_SHORT).show()
////            }
////        }
//    }
//
//    fun messageSendButtonClicked(v: View) = with(binding) {
//        Log.d("testLog", "ssk : ${readAllKeysInFile()}")
//        Log.d("testLog", "random : $random")
//
////        if (random == null) return@with
////
////        try {
////            val fis: FileInputStream? = openFileInput(keystoreFile)
////            defaultKeyStore.load(fis, storePassword)
////            fis?.close()
////
////            if (!defaultKeyStore.containsAlias(random)) {
////                Toast.makeText(this@MainActivity, "shared secret key 없음", Toast.LENGTH_SHORT).show()
////                return@with
////            }
////        }
////        catch (e: Exception) {
////            e.printStackTrace()
////        }
////
////        val userInput = messageEditText.text.toString()
////        userMessageTextView.text = userInput
////        val encryption = sdkUserStrongBox.encrypt(userInput, random!!)
////        encryptionCBCTextView.text = encryption
////        val decryption = sdkUserStrongBox.decrypt(encryption, random!!)
////        decryptionCBCTextView.text = decryption
////
////        messageEditText.text = null
//    }
//
//
//
//    fun readAllKeysInFile(): String {
////        val fis: FileInputStream?
////        val sb = StringBuffer()
////        //throw IOException
////
////        try {
////            fis = openFileInput(keystoreFile)
////            testDefaultKeyStore.load(fis, filePassword)
////            fis?.close()
////            for (key in testDefaultKeyStore.aliases()) {
////                sb.append(key)
////            }
////            return sb.toString()
////        }
////        catch (e: Exception){
////            e.printStackTrace()
////            throw e
////        }
//        return ""
//    }
//}