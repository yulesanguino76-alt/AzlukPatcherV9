package com.azluk.patcher.ai

import com.azluk.patcher.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

object AzlukAI {

    data class Result(
        val success:    Boolean,
        val suggestion: String = "",
        val error:      String = ""
    )

    suspend fun diagnose(
        errorCode: String, errorMessage: String, apkName: String, apkSizeKb: Long
    ): Result = withContext(Dispatchers.IO) {
        val apiKey = BuildConfig.TOKENROUTER_API_KEY
        if (apiKey.isBlank()) return@withContext Result(false, error = "not_configured")
        try {
            val prompt = """
Android APK install failed.
Error code: $errorCode
Error message: $errorMessage
APK: $apkName ($apkSizeKb KB)
Diagnose in 2 sentences, then give ONE concrete fix. No preamble.
""".trimIndent()

            val body = JSONObject().apply {
                put("model", BuildConfig.TOKENROUTER_MODEL)
                put("max_tokens", 250)
                put("messages", JSONArray().apply {
                    put(JSONObject().apply { put("role","system"); put("content","Android APK signing expert inside AzlukPatcher.") })
                    put(JSONObject().apply { put("role","user"); put("content", prompt) })
                })
            }
            val conn = (URL("${BuildConfig.TOKENROUTER_BASE_URL}/chat/completions")
                .openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                setRequestProperty("Content-Type","application/json")
                setRequestProperty("Authorization","Bearer $apiKey")
                doOutput = true; connectTimeout = 10000; readTimeout = 20000
            }
            conn.outputStream.use { it.write(body.toString().toByteArray()) }
            val code = conn.responseCode
            if (code !in 200..299) {
                return@withContext Result(false, error = "HTTP $code")
            }
            val text = JSONObject(conn.inputStream.bufferedReader().readText())
                .getJSONArray("choices").getJSONObject(0)
                .getJSONObject("message").getString("content").trim()
            Result(true, suggestion = text)
        } catch (e: Exception) {
            Result(false, error = e.message ?: "unknown_error")
        }
    }

    suspend fun suggestPatches(appName: String, detectedPatterns: List<String>): Result =
        withContext(Dispatchers.IO) {
            val apiKey = BuildConfig.TOKENROUTER_API_KEY
            if (apiKey.isBlank() || detectedPatterns.isEmpty()) return@withContext Result(false)
            try {
                val prompt = "App: $appName\nDetected: ${detectedPatterns.joinToString(", ")}\nRecommend priority patches in one sentence."
                val body = JSONObject().apply {
                    put("model", BuildConfig.TOKENROUTER_MODEL)
                    put("max_tokens", 100)
                    put("messages", JSONArray().apply {
                        put(JSONObject().apply { put("role","user"); put("content", prompt) })
                    })
                }
                val conn = (URL("${BuildConfig.TOKENROUTER_BASE_URL}/chat/completions")
                    .openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    setRequestProperty("Content-Type","application/json")
                    setRequestProperty("Authorization","Bearer $apiKey")
                    doOutput = true; connectTimeout = 8000; readTimeout = 15000
                }
                conn.outputStream.use { it.write(body.toString().toByteArray()) }
                if (conn.responseCode !in 200..299) return@withContext Result(false)
                val text = JSONObject(conn.inputStream.bufferedReader().readText())
                    .getJSONArray("choices").getJSONObject(0)
                    .getJSONObject("message").getString("content").trim()
                Result(true, suggestion = text)
            } catch (e: Exception) { Result(false, error = e.message ?: "") }
        }
}
