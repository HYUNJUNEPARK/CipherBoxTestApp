package com.june.strongboxkey.strongbox

object StrongBoxConstants {
    val iv: ByteArray = ByteArray(16)
    const val TAG = "applicationLog"
    const val CURVE_TYPE = "secp256r1"
    const val KEY_AGREEMENT_ALGORITHM_ECDH = "ECDH"
    const val KEYSTORE_TYPE = "AndroidKeyStore"
    const val KEYSTORE_FILE_FOR_SHARED_KEY = "keystore_shared_key"
}