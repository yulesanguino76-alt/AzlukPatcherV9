package com.azluk.patcher.ai

import android.util.Base64
import android.util.Log
import com.azluk.patcher.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * AzlukAI — diagnostic brain of AzlukPatcher.
 *
 * Three layers, tried in order:
 *
 *   1. LOCAL expert system  — zero network, zero quota, always answers
 *      for the failure modes this pipeline actually produces.
 *   2. RESPONSE CACHE       — repeated identical failures (the common
 *      case: same install error retried) never burn the free quota.
 *      TTL-bounded, in-memory only.
 *   3. REMOTE LLM           — OpenAI-compatible endpoint (Groq,
 *      OpenRouter, Google OpenAI-compat, …), configured through
 *      BuildConfig (local.properties / env at build time).
 *
 * The public API is frozen: PatchViewModel depends on these exact
 * signatures.
 */
object AzlukAI {

    private const val TAG = "AzlukAI"

    data class Result(
        val success: Boolean,
        val suggestion: String = "",
        val error: String = ""
    )

    private const val SYSTEM_PROMPT =
        "You are the built-in diagnostic expert of AzlukPatcher, an Android " +
        "APK patcher. Its pipeline: ZIP staging (config splits legitimately " +
        "have no classes.dex) -> structural DEX recipes (exact class+method " +
        "match, try/catch methods are stubbed head-only preserving " +
        "instruction boundaries) -> repack with exact byte-counter " +
        "alignment -> apksig V1/V2/V3 signing -> self-verify -> atomic " +
        "publish. Split apps are emitted as .apks containers. Diagnose " +
        "against THIS pipeline. Reply: 2-sentence diagnosis, then 'Fix:' " +
        "and ONE concrete action. No preamble."

    // ── Remote config ─────────────────────────────────────────────────────

    private fun hasKey() = BuildConfig.TOKENROUTER_API_KEY.isNotBlank()

    private fun isHttpsEndpoint(): Boolean =
        BuildConfig.TOKENROUTER_BASE_URL.startsWith("https://")

    // ── Response cache (quota protection) ────────────────────────────────

    private const val CACHE_MAX = 20
    private const val CACHE_TTL_MS = 15 * 60 * 1000L

    private class CacheEntry(
        val suggestion: String,
        val createdAt: Long
    )

    private val cache = HashMap<String, CacheEntry>()

    private fun cacheKey(prompt: String): String {
        val digest = MessageDigest.getInstance("SHA-256")

        val material = BuildConfig.TOKENROUTER_BASE_URL +
                "|" + BuildConfig.TOKENROUTER_MODEL +
                "|" + prompt

        return Base64.encodeToString(
            digest.digest(material.toByteArray()),
            Base64.NO_WRAP
        )
    }

    private fun cacheGet(key: String): String? {
        synchronized(cache) {
            val entry = cache[key] ?: return null

            if (System.currentTimeMillis() - entry.createdAt > CACHE_TTL_MS) {
                cache.remove(key)
                return null
            }

            return entry.suggestion
        }
    }

    private fun cachePut(key: String, suggestion: String) {
        synchronized(cache) {
            if (cache.size >= CACHE_MAX) {
                val oldest = cache.entries.minByOrNull { it.value.createdAt }
                if (oldest != null) {
                    cache.remove(oldest.key)
                }
            }
            cache[key] = CacheEntry(suggestion, System.currentTimeMillis())
        }
    }

    // ── Offline expert system ─────────────────────────────────────────────

    /**
     * Always-available diagnosis for the failure modes this pipeline
     * produces. Returns null when no local pattern matches — only then
     * is the remote layer consulted.
     */
    private fun localDiagnosis(error: String, context: String): String? {
        val e = error.lowercase()

        return when {
            "verification_failure" in e ->
                "The system package verifier rejected the APK. This is " +
                "normal for patched apps. Fix: uninstall the original " +
                "app first (different signature), then install; if it " +
                "persists, disable Play Protect scanning. ($context)"

            "missing splits" in e ->
                "The original app is installed with split APKs. Fix: " +
                "install the .apks container from Patched Files — it " +
                "includes base + all splits — after uninstalling the " +
                "original. ($context)"

            "install_failed_version_downgrade" in e ->
                "The patched build has a lower versionCode than the one " +
                "installed. Fix: uninstall the original app, then " +
                "install the patched output. ($context)"

            "no_matching_abis" in e || "no compatible abis" in e ->
                "The device ABI has no matching native library split. " +
                "Fix: patch and install the FULL .apks container so all " +
                "ABI splits are present; do not install a lone base " +
                "from an app shipped with split ABIs. ($context)"

            "install_failed_dexopt" in e ->
                "The installer rejected DEX optimization. Fix: re-patch " +
                "with only the needed patches and check the log for a " +
                "DEX validation error before publishing. ($context)"

            "install_failed_aborted" in e ->
                "The install was aborted mid-flight, usually storage or " +
                "an interrupted transfer. Fix: free space, re-copy the " +
                "file and retry. ($context)"

            "signature" in e && "conflict" in e ||
                    "install_failed_update_incompatible" in e ->
                "Signature mismatch with the installed version. Fix: " +
                "uninstall the original app, then install the patched " +
                "output. ($context)"

            "invalid" in e && ("apk" in e || "package" in e) ||
                    "parse" in e && "package" in e ->
                "The installer could not parse the package. Fix: " +
                "re-patch and watch the log for DEX/signing errors; " +
                "Keystore can also transiently fail — one retry is " +
                "worth it. ($context)"

            "insufficient" in e && "storage" in e ->
                "Not enough storage. Fix: free space and retry. ($context)"

            "blocked" in e ->
                "Install blocked by the system. Fix: enable 'Install " +
                "unknown apps' for AzlukPatcher in Settings. ($context)"

            "no dex" in e || "dex magic" in e ->
                "A staged entry lacked valid DEX. Config splits have no " +
                "classes.dex — that is logged and safe. If this came " +
                "from the BASE apk, the input is corrupted. ($context)"

            "signing" in e || "keystore" in e ->
                "Signing failed. Fix: retry once; if persistent, the " +
                "device Keystore entry may be stale — rebooting the " +
                "device usually recovers it. ($context)"

            "timeout" in e || "timed out" in e ->
                "A phase timed out — the file is large or the device is " +
                "under load. Fix: close background apps and retry. ($context)"

            "zipexception" in e || "zip exception" in e ->
                "A ZIP entry failed to read — the input container is " +
                "truncated. Fix: re-import the original file and " +
                "re-patch. ($context)"

            "outofmemory" in e || "out of memory" in e ->
                "Ran out of heap while staging. Fix: patch a smaller " +
                "file first, close other apps, retry. ($context)"

            else -> null
        }
    }

    /**
     * Patch-log lines that are INFORMATIONAL, not failures: matching
     * them avoids burning a remote call on a healthy run.
     */
    private fun isInformationalLog(logLines: List<String>): Boolean {
        if (logLines.isEmpty()) return false

        val tail = logLines.takeLast(3).joinToString(" ").lowercase()

        return "no structural recipe matched" in tail &&
                "[error]" !in tail &&
                "exception" !in tail
    }

    // ── Local patch priority (suggestPatches offline path) ───────────────

    private fun localPriority(detectedKeys: List<String>): String? {
        if (detectedKeys.isEmpty()) return null

        val order = listOf(
            "REMOVE_ADS",
            "DISABLE_ANALYTICS",
            "REMOVE_TELEMETRY",
            "FORCE_DEBUGGABLE",
            "ALLOW_BACKUP",
            "SSL_BYPASS",
            "ROOT_BYPASS",
            "IAP_BYPASS",
            "LICENSE_BYPASS",
            "SIGNATURE_BYPASS",
            "GOOGLE_PLAY_BYPASS"
        )

        val sorted = detectedKeys.sortedBy { key ->
            order.indexOf(key).let { if (it == -1) order.size else it }
        }

        return "Start with ${sorted.first().lowercase().replace('_', ' ')} " +
                "— highest impact for this app — then review the rest: " +
                sorted.drop(1).joinToString(", ") { it.lowercase() } + "."
    }

    // ── HTTP layer ────────────────────────────────────────────────────────

    /**
     * Bounded log tail: last 30 lines, each capped, so the request
     * payload never balloons on big patch runs.
     */
    private fun boundedLogTail(logLines: List<String>): String {
        return logLines
            .takeLast(30)
            .joinToString("\n") { it.take(200) }
    }

    private fun post(prompt: String, maxTokens: Int): Result {
        val body = JSONObject().apply {
            put("model", BuildConfig.TOKENROUTER_MODEL)
            // Groq-current field; legacy providers may reject it — the
            // one-shot fallback below covers them.
            put("max_completion_tokens", maxTokens)
            put("messages", JSONArray().apply {
                put(JSONObject().apply {
                    put("role", "system"); put("content", SYSTEM_PROMPT)
                })
                put(JSONObject().apply {
                    put("role", "user"); put("content", prompt)
                })
            })
        }

        val first = postOnce(body.toString())

        if (first.success) return first

        /*
         * One-shot compat retry: only when the server explicitly
         * complained about the token field (non-Groq OpenAI-compatible
         * providers that predate max_completion_tokens).
         */
        val detail = first.error.lowercase()

        if (detail.contains("max_completion_tokens") ||
                detail.contains("max_tokens") && detail.contains("unknown")) {

            val legacy = JSONObject(body.toString()).apply {
                remove("max_completion_tokens")
                put("max_tokens", maxTokens)
            }

            return postOnce(legacy.toString())
        }

        /*
         * Rate limited: single polite retry after a short backoff.
         */
        if (detail.contains("429") || detail.contains("rate limit")) {
            try {
                Thread.sleep(2500)
            } catch (_: InterruptedException) {
            }
            return postOnce(body.toString())
        }

        return first
    }

    private fun postOnce(requestBody: String): Result {
        var conn: HttpURLConnection? = null

        try {
            conn = (URL(
                "${BuildConfig.TOKENROUTER_BASE_URL}/chat/completions"
            ).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty(
                    "Authorization",
                    "Bearer ${BuildConfig.TOKENROUTER_API_KEY}"
                )
                doOutput = true
                connectTimeout = 10_000
                readTimeout = 20_000
            }

            conn.outputStream.use {
                it.write(requestBody.toByteArray())
            }

            val code = conn.responseCode

            if (code !in 200..299) {
                val errBody = runCatching {
                    conn.errorStream
                        ?.bufferedReader()
                        ?.readText()
                        ?.take(300)
                }.getOrNull().orEmpty()

                return Result(
                    false,
                    error = "HTTP $code: $errBody"
                )
            }

            val text = JSONObject(
                conn.inputStream.bufferedReader().readText()
            )
                .getJSONArray("choices")
                .getJSONObject(0)
                .getJSONObject("message")
                .getString("content")
                .trim()

            return Result(true, suggestion = text)
        } catch (e: Exception) {
            return Result(false, error = e.message ?: "network_error")
        } finally {
            conn?.disconnect()
        }
    }

    private fun remote(prompt: String, maxTokens: Int): Result {
        if (!hasKey()) {
            return Result(false, error = "not_configured")
        }

        if (!isHttpsEndpoint()) {
            return Result(false, error = "endpoint must be https")
        }

        val key = cacheKey(prompt)

        cacheGet(key)?.let { return Result(true, suggestion = it) }

        val result = try {
            post(prompt, maxTokens)
        } catch (e: Exception) {
            Result(false, error = e.message ?: "unknown_error")
        }

        if (result.success) {
            cachePut(key, result.suggestion)
        } else {
            Log.w(TAG, "remote diagnosis unavailable: ${result.error}")
        }

        return result
    }

    // ── Public API (frozen — PatchViewModel depends on these) ────────────

    suspend fun diagnose(
        errorCode: String,
        errorMessage: String,
        apkName: String,
        apkSizeKb: Long
    ): Result = withContext(Dispatchers.IO) {
        val context = "$apkName (${apkSizeKb} KB)"

        localDiagnosis("$errorCode $errorMessage", context)?.let {
            return@withContext Result(true, suggestion = it)
        }

        remote(
            """
            Android APK install failed.
            Error code: $errorCode
            Error message: $errorMessage
            APK: $apkName ($apkSizeKb KB)
            """.trimIndent(),
            250
        )
    }

    suspend fun analyzePatchLog(
        error: String,
        logLines: List<String>
    ): Result = withContext(Dispatchers.IO) {
        /*
         * Healthy no-match run: informational, never a remote call.
         */
        if (isInformationalLog(logLines)) {
            return@withContext Result(
                true,
                suggestion = "The run completed cleanly — no structural " +
                    "recipe matched this app, so the output is a " +
                    "byte-faithful repack. Nothing failed."
            )
        }

        localDiagnosis(error, "patch pipeline")?.let {
            return@withContext Result(true, suggestion = it)
        }

        remote(
            """
            AzlukPatcher patch run FAILED.
            Exception: $error
            Patch log (last 30 lines, each capped):
            ${boundedLogTail(logLines)}
            Identify the failing pipeline stage and the concrete fix.
            """.trimIndent(),
            300
        )
    }

    suspend fun suggestPatches(
        appName: String,
        detectedKeys: List<String>
    ): Result = withContext(Dispatchers.IO) {
        localPriority(detectedKeys)?.let {
            return@withContext Result(true, suggestion = it)
        }

        remote(
            "App: $appName\nDetected patches: " +
                    "${detectedKeys.joinToString(", ")}\n" +
                    "Recommend priority in one sentence.",
            120
        )
    }
}
