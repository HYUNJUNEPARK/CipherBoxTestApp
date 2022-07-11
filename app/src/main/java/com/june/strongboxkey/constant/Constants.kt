package com.june.strongboxkey.constant

object Constants {
    const val KEY_GEN_ALGORITHM = "EC"
    const val CURVE_TYPE = "secp256r1"
    const val KEY_AGREEMENT_ALGORITHM = "ECDH"
    const val KEY_ALGORITHM = "AES"
    const val CIPHER_ECB_ALGORITHM = "AES/ECB/PKCS5Padding"
    const val CIPHER_CBC_ALGORITHM = "AES/CBC/PKCS7Padding"
    const val MESSAGE_DIGEST_ALGORITHM = "SHA-256"

    //TODO check is it possible null ? and move to AESUtil
    lateinit var IV: ByteArray
}