package com.study.cipherbox.app

import android.os.Build

object Util {
    fun checkDeviceVersion(): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
    }
}