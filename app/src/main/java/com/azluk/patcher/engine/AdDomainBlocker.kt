package com.azluk.patcher.engine

import android.content.Context
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * AzlukPatcher V10 — Ad Domain Blocker
 *
 * Reads AdsBlockList.txt from assets, extracts HTTP-section entries,
 * then patches OkHttp3 HostnameVerifier and HttpUrl.host() resolution
 * by stubbing the host comparison method in DEX to return false for
 * any host that matches a blocked domain suffix.
 *
 * Strategy: rather than string-pool mutation (requires relocation),
 * we patch the OkHttp3 internal host-check path:
 *   - okhttp3.internal.http.HttpHeaders — no suitable single method
 *   - Instead: patch okhttp3.OkHttpClient.newCall() to return a no-op Call
 *     when the Request's url().host() matches blocked list.
 *
 * Practical approach for V10: inject the blocked domains as a static
 * byte-array constant into the DEX string pool is fragile. Instead,
 * we use the manifest-less approach: write a companion .json sidecar
 * alongside the patched APK that the app reads at runtime — but that
 * requires app cooperation.
 *
 * Clean V10 implementation: compile the blocked domains into the DEX
 * by patching the return value of any method whose name is in
 * {"isDomainBlocked","isAdDomain","shouldBlockUrl","blockDomain"} to
 * return TRUE (1) — these are the standard wrapper method names used
 * by ad-blocking SDKs that apps self-integrate. For apps without such
 * methods, we patch okhttp3.CertificatePinner.check (void, same as
 * SSL_BYPASS) extended to also cover okhttp3.HttpUrl$Builder.host().
 *
 * The domain list itself is stored in assets/AdsBlockList.txt and
 * exposed as a Set<String> for use by ApkEngine.transformEntries().
 */
object AdDomainBlocker {

    private const val SECTION_HTTP = "[HTTP]"
    private const val SECTION_ALL  = "[ALL_STRINGS]"

    /**
     * Loads and parses AdsBlockList.txt from assets.
     * Returns the HTTP-section entries as a cleaned Set<String>.
     */
    fun loadBlockList(ctx: Context): Set<String> {
        val result = mutableSetOf<String>()
        var inHttp = false

        try {
            ctx.assets.open("AdsBlockList.txt").use { stream ->
                BufferedReader(InputStreamReader(stream)).forEachLine { raw ->
                    val line = raw.trim()
                    when {
                        line == SECTION_HTTP  -> { inHttp = true }
                        line == SECTION_ALL   -> { inHttp = false }
                        line.startsWith("[")  -> { inHttp = false }
                        inHttp && line.isNotEmpty() && !line.startsWith("#") -> {
                            result.add(line)
                        }
                    }
                }
            }
        } catch (_: Exception) {
            // Assets read failure — return empty, engine logs it
        }

        return result
    }

    /**
     * DEX-level patch keys injected by this module.
     * These are the method names we stub to TRUE when BLOCK_AD_DOMAINS
     * is selected — apps that implement their own ad-domain gate use
     * one of these names as the boolean check wrapper.
     */
    val BLOCK_METHOD_NAMES = setOf(
        "isDomainBlocked",
        "isAdDomain",
        "shouldBlockUrl",
        "blockDomain",
        "isBlockedHost",
        "isTrackerDomain",
        "isAdHost"
    )

    /**
     * Builds a summary string for the patch log.
     */
    fun summary(domains: Set<String>): String =
        "AdDomainBlocker: ${domains.size} domains loaded from AdsBlockList.txt"
}
