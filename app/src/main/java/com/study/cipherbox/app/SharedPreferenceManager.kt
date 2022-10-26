package com.study.cipherbox.app

import android.content.Context
import android.content.SharedPreferences

class SharedPreferenceManager {
    companion object {
        const val PREFERENCE_NAME = "pref"
        private var instance: SharedPreferenceManager? = null
        private lateinit var context: Context
        private lateinit var prefs: SharedPreferences
        private lateinit var prefsEditor: SharedPreferences.Editor

        fun getInstance(_context: Context): SharedPreferenceManager? {
            if (instance == null) {
                context = _context
                instance = SharedPreferenceManager()
            }
            return instance
        }
    }

    init {
        prefs = context.getSharedPreferences(PREFERENCE_NAME, Context.MODE_PRIVATE)
        prefsEditor = prefs.edit()
    }

    fun getString(key: String?, defValue: String?): String {
        return prefs.getString(key, defValue)!!
    }

    fun putString(key: String?, value: String?) {
        prefsEditor.apply {
            putString(key, value)
            apply()
        }
    }

    fun getInt(key: String?, defValue: Int): Int {
        return prefs.getInt(key, defValue)
    }

    fun putInt(key: String?, value: Int?) {
        prefsEditor.apply {
            putInt(key, value!!)
            apply()
        }
    }

    fun getBoolean(key: String?, defValue: Boolean): Boolean {
        return prefs.getBoolean(key, defValue)
    }

    fun putBoolean(key: String?, value: Boolean) {
        prefsEditor.apply {
            putBoolean(key, value)
            apply()
        }
    }
}