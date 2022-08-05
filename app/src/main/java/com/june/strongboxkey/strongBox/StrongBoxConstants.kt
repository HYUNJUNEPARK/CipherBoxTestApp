package com.june.strongboxkey.strongBox

object StrongBoxConstants {
    val iv: ByteArray = ByteArray(16)

    const val CIPHER_AES_ECB_PADDING = "AES/ECB/PKCS5Padding"
    const val CIPHER_AES_CBC_PADDING = "AES/CBC/PKCS7Padding"

    const val KEY_AGREEMENT_ALGORITHM_ECDH = "ECDH"
    const val CURVE_TYPE = "secp256r1"

    //keystore
    const val KEYSTORE_TYPE = "AndroidKeyStore"


    const val TAG = "applicationLog"

}