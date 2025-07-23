package com.momen.securitypractice

import android.annotation.SuppressLint
import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.momen.securitypractice.databinding.FragmentFirstBinding

class FirstFragment : Fragment() {

    private var _binding: FragmentFirstBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {

        _binding = FragmentFirstBinding.inflate(inflater, container, false)
        return binding.root

    }

    @SuppressLint("SetTextI18n")
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val secretKey = Encryptor.generateAESKey()

        var encryptedAESText = ""
        var currentIVHex = ""

        binding.btnAESEncrypt.setOnClickListener {
            val textToEncrypt = binding.etTextToEncrypt.text.toString()
            if (textToEncrypt.isEmpty()) return@setOnClickListener
            try {
                val (encryptedBytes, ivBytes) = Encryptor.encryptAES(
                    secretKey,
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

                val decryptedBytes = Encryptor.decryptAES(secretKey, encryptedBytes, ivBytes)
                binding.tvAesResult.text = "Decrypted:\n${String(decryptedBytes)}"
            } catch (e: Exception) {
                binding.tvAesResult.text = "Decryption failed: ${e.message}"
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}