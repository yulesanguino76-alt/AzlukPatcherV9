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
        val success: Boolean,
        val suggestion: String = "",
        val error: String = ""
    )

    private const val SYSTEM_PROMPT =
        "You are the built-in diagnostic expert of AzlukPatcher, an Android " +
        "APK patcher. Its pipeline: ZIP staging (config splits legitimately " +
        "have no classes.dex) -> structural DEX recipes (exact class+method " +
        "match, methods with try/catch are skipped) -> repack with exact " +
        "byte-counter alignment -> apksig V1/V2/V3 signing -> self-verify -> " +
        "atomic publish. Split apps are emitted as .apks containers. Diagnose " +
        "against THIS pipeline. Reply: 2-sentence diagnosis, then 'Fix:' and " +
        "ONE concrete action. No preamble."

    private fun hasKey() = BuildConfig.TOKENROUTER_API_KEY.isNotBlank()

    private fun post(prompt: String, maxTokens: Int): Result {
        val body = JSONObject().apply {
            put("model", BuildConfig.TOKENROUTER_MODEL)
            put("max_tokens", maxTokens)
            put("messages", JSONArray().apply {
                put(JSONObject().apply {
                    put("role", "system"); put("content", SYSTEM_PROMPT)
                })
                put(JSONObject().apply {
                    put("role", "user"); put("content", prompt)
                })
            })
        }

        val conn = (URL("${BuildConfig.TOKENROUTER_BASE_URL}/chat/completions")
            .openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Authorization", "Bearer ${BuildConfig.TOKENROUTER_API_KEY}")
            doOutput = true
            connectTimeout = 10000
            readTimeout = 20000
        }

        conn.outputStream.use { it.write(body.toString().toByteArray()) }

        val code = conn.responseCode
        if (code !in 200..299) {
            return Result(false, error = "HTTP $code")
        }

        val text = JSONObject(conn.inputStream.bufferedReader().readText())
            .getJSONArray("choices").getJSONObject(0)
            .getJSONObject("message").getString("content").trim()

        return Result(true, suggestion = text)
    }

    /**
     * Install-failure diagnosis (PatchedFilesScreen install log).
     */
    suspend fun diagnose(
        errorCode: String, errorMessage: String, apkName: String, apkSizeKb: Long
    ): Result = withContext(Dispatchers.IO) {
        if (!hasKey()) return@withContext Result(false, error = "not_configured")
        try {
            val prompt = """
                Android APK install failed.
                Error code: $errorCode
                Error message: $errorMessage
                APK: $apkName ($apkSizeKb KB)
            """.trimIndent()
            post(prompt, 250)
        } catch (e: Exception) {
            Result(false, error = e.message ?: "unknown_error")
        }
    }

    /**
     * Patch-failure analysis: feed the ACTUAL patch log + the thrown
     * error so the model diagnoses the real pipeline stage that broke.
     * Called automatically by PatchViewModel on any patch failure.
     */
    suspend fun analyzePatchLog(
        error: String,
        logLines: List<String>
    ): Result = withContext(Dispatchers.IO) {
        if (!hasKey()) return@withContext Result(false, error = "not_configured")
        try {
            val tail = logLines.takeLast(40).joinToString("\n")
            val prompt = """
                AzlukPatcher patch run FAILED.
                Exception: $error

                Patch log (last ${logLines.size.coerceAtMost(40)} lines):
                $tail

                Identify the failing pipeline stage and the concrete fix.
            """.trimIndent()
            post(prompt, 300)
        } catch (e: Exception) {
            Result(false, error = e.message ?: "unknown_error")
        }
    }

    /**
     * One-sentence patch priority hint after a successful scan.
     */
    suspend fun suggestPatches(appName: String, detectedKeys: List<String>): Result =
        withContext(Dispatchers.IO) {
            if (!hasKey() || detectedKeys.isEmpty()) {
                return@withContext Result(false)
            }
            try {
                post(
                    "App: $appName\nDetected patches: ${detectedKeys.joinToString(", ")}\n" +
                            "Recommend priority in one sentence.",
                    120
                )
            } catch (e: Exception) {
                Result(false, error = e.message ?: "")
            }
        }
}
