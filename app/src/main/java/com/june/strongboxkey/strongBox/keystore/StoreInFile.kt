package com.june.strongboxkey.strongBox.keystore

import android.content.Context
import android.util.Log
import com.june.strongboxkey.strongBox.StrongBoxConstants.KEYSTORE_FILE_FOR_SHARED_KEY
import com.june.strongboxkey.strongBox.StrongBoxConstants.TAG
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.Key
import java.security.KeyStore

class StoreInFile(private val context: Context) {
//https://stackoverflow.com/questions/24231213/how-to-store-secretkey-in-keystore-and-retrieve-it

    //자바을 이용한 암호학 - 7
    //https://bigdown.tistory.com/129

    //KeyStore.getDefaultType() == BKS
    private val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
        var fis: FileInputStream? = null
        try {
            fis = context.openFileInput(KEYSTORE_FILE_FOR_SHARED_KEY)
        }
        catch (e: Exception){
            load(null)
        }
        load(fis, storePasswd)
    }
    private val storePasswd = "storePassword".toCharArray()
    private val keyPasswd = "keyPassword".toCharArray()

    fun storeKeystoreInFile(keyAlias: String, key: Key) {
        keyStore.setKeyEntry(keyAlias, key, keyPasswd, null)
        val ksOut: FileOutputStream = context.openFileOutput(KEYSTORE_FILE_FOR_SHARED_KEY, Context.MODE_PRIVATE)
        keyStore.store(ksOut, storePasswd)
        ksOut.close()
    }




    fun isKeyStoreFile(keyAlias: String): Boolean {
        var fis: FileInputStream
        try {
            fis = context.openFileInput(KEYSTORE_FILE_FOR_SHARED_KEY)
        }
        catch (e: Exception){
            e.printStackTrace()
            return false
        }
        keyStore.load(fis, storePasswd)
        keyStore.getKey(keyAlias, storePasswd).let { key ->
            return key != null
        }
    }

    fun readAllKeysInFile() {
        var fis: FileInputStream? = null
        try {
            fis = context.openFileInput(KEYSTORE_FILE_FOR_SHARED_KEY)
        }
        catch (e: Exception){
            e.printStackTrace()
            return
        }
        keyStore.load(fis, storePasswd)
        Log.d(TAG, "readAllKeyFileList Size : ${keyStore.size()}")
        //TODO TEST
        for (key in keyStore.aliases()) {
            Log.d(TAG, "readAllKeyFileList: $key")
        }
    }

    fun getKey(keyAlias: String): Key {
        var fis: FileInputStream? = null
        try {
            fis = context.openFileInput(KEYSTORE_FILE_FOR_SHARED_KEY)
        }
        catch (e: Exception){
        }
        keyStore.load(fis, storePasswd)
        return keyStore.getKey(keyAlias, keyPasswd)
    }
}