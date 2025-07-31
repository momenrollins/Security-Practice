package com.momen.securitypractice

import android.util.Base64


/**
 * to Base64
 */

fun ByteArray.toBase64String() = Base64.encodeToString(this, Base64.DEFAULT or Base64.NO_WRAP)

/**
 * to Hex String
 */
fun ByteArray.toHexString() = joinToString(separator = "") { String.format("%02x", it) }
