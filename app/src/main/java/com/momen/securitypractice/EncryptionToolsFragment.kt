package com.momen.securitypractice

import android.annotation.SuppressLint
import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.momen.securitypractice.databinding.FragmentEncryptionToolsBinding
import java.util.UUID

class EncryptionToolsFragment : Fragment() {

    private var _binding: FragmentEncryptionToolsBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {

        _binding = FragmentEncryptionToolsBinding.inflate(inflater, container, false)
        return binding.root

    }

    @SuppressLint("SetTextI18n")
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        /**
         * AES
         */
        val secretAESKey = Encryptor.generateAESKey()

        var encryptedAESText = ""
        var currentIVHex = ""

        binding.btnAESEncrypt.setOnClickListener {
            val textToEncrypt = binding.etTextToEncrypt.text.toString()
            if (textToEncrypt.isEmpty()) return@setOnClickListener
            try {
                val (encryptedBytes, ivBytes) = Encryptor.encryptAES(
                    secretAESKey,
                    textToEncrypt.toByteArray()
                )
                currentIVHex = ivBytes.joinToString(separator = "") { String.format("%02x", it) }
                encryptedAESText =
                    encryptedBytes.joinToString(separator = "") { String.format("%02x", it) }
                binding.tvAesResult.text = "Encrypted:\n$encryptedAESText\n\nIV:\n$currentIVHex"
            } catch (e: Exception) {
                binding.tvAesResult.text = "Encryption failed: ${e.message}"
            }
        }

        binding.btnAESDecrypt.setOnClickListener {
            if (encryptedAESText.isEmpty() || currentIVHex.isEmpty()) return@setOnClickListener
            try {
                val encryptedBytes =
                    encryptedAESText.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                val ivBytes = currentIVHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

                val decryptedBytes = Encryptor.decryptAES(secretAESKey, encryptedBytes, ivBytes)
                binding.tvAesResult.text = "Decrypted:\n${String(decryptedBytes)}"
            } catch (e: Exception) {
                binding.tvAesResult.text = "Decryption failed: ${e.message}"
            }
        }

        /**
         * RSA
         */

        val publicKey = Encryptor.getRSAPublicKey()
        val privateKey = Encryptor.getRSAPrivateKey()

        var encryptedRSAText = ""

        binding.btnRsaEncrypt.setOnClickListener {
            val textToEncrypt = binding.etTextToEncrypt.text.toString()
            if (textToEncrypt.isEmpty()) return@setOnClickListener
            try {
                val encryptedBytes = Encryptor.encryptRSA(publicKey, textToEncrypt.toByteArray())
                encryptedRSAText =
                    encryptedBytes.joinToString(separator = "") { String.format("%02x", it) }
                binding.tvRsaResult.text = "Encrypted:\n$encryptedRSAText"
            } catch (e: Exception) {
                binding.tvRsaResult.text = "Encryption failed: ${e.message}"
            }
        }

        binding.btnRsaDecrypt.setOnClickListener {
            if (encryptedRSAText.isEmpty()) return@setOnClickListener
            try {
                val encryptedBytes =
                    encryptedRSAText.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                val decryptedBytes = Encryptor.decryptRSA(privateKey, encryptedBytes)
                binding.tvRsaResult.text = "Decrypted:\n${String(decryptedBytes)}"
            } catch (e: Exception) {
                binding.tvRsaResult.text = "Decryption failed: ${e.message}"
            }
        }

        /**
         * SHA-256
         */

        val challenge = UUID.randomUUID().toString()
        val issuerScript = "Momen"
        binding.btnSha256.setOnClickListener {
            val textToHash = binding.etTextToEncrypt.text.toString()
            if (textToHash.isEmpty()) return@setOnClickListener
            try {
                val dataToHash = textToHash + challenge + issuerScript
                val hashedBytes = Encryptor.sha256(dataToHash.toByteArray())
                binding.tvSha256Result.text =
                    hashedBytes.joinToString(separator = "") { String.format("%02x", it) }
            } catch (e: Exception) {
                binding.tvSha256Result.text = "Hashing failed: ${e.message}"
            }
        }

    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}