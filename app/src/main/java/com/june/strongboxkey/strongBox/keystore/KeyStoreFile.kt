package com.june.strongboxkey.strongBox.keystore

import android.content.Context
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.Key
import java.security.KeyStore

class KeyStoreFile(private val context: Context) {
    private val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
    private val passwordKS = "mKeyStore".toCharArray()

    fun storeKey(keyStoreAlias: String, key: Key) {
        keyStore.setKeyEntry(keyStoreAlias, key, passwordKS, null)

        val ksout: FileOutputStream = context.openFileOutput("keyStoreName", Context.MODE_PRIVATE)
        keyStore.store(ksout, passwordKS)
        ksout.close()
    }

    fun getKey(keyStoreAlias: String): Key {
        var fis: FileInputStream? = null

        try {
            fis = context.openFileInput("keyStoreName")
        }
        catch (e: Exception){
        }
        keyStore.load(fis, passwordKS)
        return keyStore.getKey(keyStoreAlias, passwordKS)

        //return keyStore.getKey(keyStoreAlias, passwordKS)
    }


    //    //TEST
//    companion object {
//        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
//            load(null)
//        }
//    }
//    //TEST

    //TEST
    //https://stackoverflow.com/questions/24231213/how-to-store-secretkey-in-keystore-and-retrieve-it
//       val passwordKS = "wshr.ut".toCharArray()
//       keyStore.setKeyEntry("aaaaa", key, passwordKS, null)
//       val sk = keyStore.getKey("aaaaa", passwordKS)
    //keyStore.store()
    //keyStore.containsAlias(KeyStore.getDefaultType())
    //TEST

//        //test
//        val passwordKS = "wshr.ut".toCharArray()
//        val sk = keyStore.getKey("aaaaa", passwordKS)
//        if (keyStore.containsAlias("aaaaa")) {
//            Log.d("testLog", "decryptionCBCMode: success")
//        }
//        else {
//            Log.d("testLog", "decryptionCBCMode: failed")
//        }
//        //test

}