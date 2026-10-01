package com.azluk.patcher.engine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.Adler32;

/**
 * AzlukPatcher V9 - SuperDexPatcher
 *
 * DEX parser/transformer, failure-loud by design:
 *
 *  - validates the DEX header before reading tables
 *  - uses the real DEX offsets from the specification
 *  - decodes DEX strings as strict MUTF-8
 *  - resolves methods structurally through class_defs -> class_data ->
 *    method_ids -> name_idx -> string_ids; never through const-string scans
 *  - never touches ACC_NATIVE or ACC_ABSTRACT methods
 *  - refuses methods with exception handlers (tries_size != 0)
 *  - recomputes SHA-1 + Adler32 only after successful mutation
 *
 * DETECTION has two layers, unioned:
 *
 *  1. Structural: exact descriptor presence in type_ids (DETECTORS map,
 *     built generically from RECIPES).
 *
 *  2. Marker scan (V8-compatible): UTF-8 byte substrings that only exist
 *     in a DEX when the corresponding SDK is linked in — class descriptors
 *     and well-known constant names live verbatim in the string pool.
 *     A marker hit means the patch is AVAILABLE, nothing more.
 *
 * PATCHING stays strict regardless of detection: every candidate is
 * re-verified structurally (exact descriptor + exact method + return
 * guard), and keys without a structural recipe no-op with a loud log
 * line — a detection hit can never corrupt a DEX.
 *
 * STUBS are type-aware AND verdict-aware: return-void, const/4 + return
 * for primitives (with a configurable stubValue — 0 == OK/SUCCESS/false,
 * 1 == true), null object returns, and zero wide returns.
 */
public final class SuperDexPatcher {

    private SuperDexPatcher() {
    }

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    private static final int HEADER_SIZE = 0x70;
    private static final int CLASS_DEF_SIZE = 32;
    private static final int METHOD_ID_SIZE = 8;
    private static final int PROTO_ID_SIZE = 12;
    private static final int TYPE_ID_SIZE = 4;

    private static final int DEX_ENDIAN_CONSTANT = 0x12345678;

    private static final int ACC_NATIVE = 0x0100;
    private static final int ACC_ABSTRACT = 0x0400;

    private static final int ATTR_DEBUGGABLE = 0x0101021b;
    private static final int ATTR_EXPORTED = 0x010102d4;
    private static final int ATTR_ALLOW_BACKUP = 0x010100d1;
    private static final int ATTR_FULL_BACKUP_ONLY = 0x010104eb;

    private static final int RES_STRING_POOL_TYPE = 0x0001;
    private static final int RES_XML_RESOURCE_MAP_TYPE = 0x0180;
    private static final int RES_XML_START_ELEMENT_TYPE = 0x0102;

    private static final int TYPE_INT_BOOLEAN = 0x12;

    public interface Progress {
        void log(String message);
    }

    /**
     * Marker table — V8-compatible detection layer.
     *
     * marker -> patch key. Markers are ASCII substrings of MUTF-8 DEX
     * strings, so they appear verbatim as bytes in the file.
     */
    private static final String[][] MARKERS = {
            /* Licensing */
            { "LICENSE_BYPASS",      "ILicensingService" },
            { "LICENSE_BYPASS",      "com/google/android/vending/licensing" },
            { "LICENSE_BYPASS",      "LICENSED" },

            /* Play Billing */
            { "IAP_BYPASS",          "com/android/vending/billing" },
            { "IAP_BYPASS",          "BillingClient" },
            { "IAP_BYPASS",          "PURCHASED" },

            /* Signature checks */
            { "SIGNATURE_BYPASS",    "getSignatures" },
            { "SIGNATURE_BYPASS",    "GET_SIGNATURES" },
            { "SIGNATURE_BYPASS",    "signingInfo" },

            /* Ad SDKs */
            { "REMOVE_ADS",          "com/google/android/gms/ads" },
            { "REMOVE_ADS",          "com/facebook/ads" },
            { "REMOVE_ADS",          "com/unity3d/ads" },
            { "REMOVE_ADS",          "com/applovin" },
            { "REMOVE_ADS",          "com/ironsource" },
            { "REMOVE_ADS",          "com/mopub" },
            { "REMOVE_ADS",          "com/chartboost" },
            { "REMOVE_ADS",          "com/vungle" },
            { "REMOVE_ADS",          "com/inmobi" },

            /* TLS pinning / trust managers */
            { "SSL_BYPASS",          "CertificatePinner" },
            { "SSL_BYPASS",          "checkServerTrusted" },
            { "SSL_BYPASS",          "checkClientTrusted" },
            { "SSL_BYPASS",          "javax/net/ssl/X509TrustManager" },

            /* Root detection */
            { "ROOT_BYPASS",         "isRooted" },
            { "ROOT_BYPASS",         "RootBeer" },
            { "ROOT_BYPASS",         "isDeviceRooted" },
            { "ROOT_BYPASS",         "/system/xbin/su" },

            /* Integrity attestation */
            { "SAFETYNET_BYPASS",    "SafetyNet" },
            { "SAFETYNET_BYPASS",    "com/google/android/play/core/integrity" },

            /* Anti-Frida / anti-Xposed */
            { "FRIDA_BYPASS",        "frida" },
            { "FRIDA_BYPASS",        "XposedBridge" },
            { "FRIDA_BYPASS",        "tracerpid" },

            /* Screenshot blocking */
            { "DISABLE_FLAG_SECURE", "FLAG_SECURE" }
    };

    /**
     * Structural recipes. Exact descriptor match, exact method name match,
     * optional expected return type guard, configurable stub verdict.
     * First matching recipe wins.
     */
    private static final List<Recipe> RECIPES;

    static {
        List<Recipe> recipes = new ArrayList<>();

        /* ── Analytics ─────────────────────────────────────────────────── */

        recipes.add(new Recipe(
                "DISABLE_ANALYTICS",
                new String[]{ "Lcom/google/firebase/analytics/FirebaseAnalytics;" },
                new String[]{ "logEvent" },
                "V"));

        recipes.add(new Recipe(
                "DISABLE_ANALYTICS",
                new String[]{ "Lcom/mixpanel/android/mpmetrics/MixpanelAPI;" },
                new String[]{ "track", "trackMap" },
                "V"));

        /* ── Telemetry ─────────────────────────────────────────────────── */

        recipes.add(new Recipe(
                "REMOVE_TELEMETRY",
                new String[]{ "Lio/sentry/Sentry;" },
                new String[]{ "captureException", "captureMessage", "captureEvent" },
                null));

        recipes.add(new Recipe(
                "REMOVE_TELEMETRY",
                new String[]{ "Lcom/google/firebase/crashlytics/FirebaseCrashlytics;" },
                new String[]{ "recordException", "log" },
                "V"));

        recipes.add(new Recipe(
                "REMOVE_TELEMETRY",
                new String[]{ "Lcom/bugsnag/android/Bugsnag;" },
                new String[]{ "notify" },
                null));

        /* ── Ads: legacy GMA SDK ───────────────────────────────────────── */

        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{ "Lcom/google/android/gms/ads/AdView;" },
                new String[]{ "loadAd" },
                "V"));

        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/google/android/gms/ads/InterstitialAd;",
                        "Lcom/google/android/gms/ads/AppOpenAd;",
                        "Lcom/google/android/gms/ads/rewarded/RewardedAd;"
                },
                new String[]{ "show" },
                "V"));

        /*
         * Ads: modern GMA SDK (v20+). The entry-point classes moved into
         * subpackages — banner/, interstitial/, appopen/, rewarded/.
         */
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{ "Lcom/google/android/gms/ads/banner/BannerView;" },
                new String[]{ "loadAd" },
                "V"));

        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/google/android/gms/ads/interstitial/InterstitialAd;",
                        "Lcom/google/android/gms/ads/rewarded/RewardedAd;",
                        "Lcom/google/android/gms/ads/appopen/AppOpenAd;"
                },
                new String[]{ "show" },
                "V"));

        /* ── Ads: Facebook / Unity / AppLovin / IronSource / MoPub ─────── */

        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/facebook/ads/AdView;",
                        "Lcom/facebook/ads/BannerAdView;"
                },
                new String[]{ "loadAd" },
                "V"));

        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/facebook/ads/InterstitialAd;",
                        "Lcom/facebook/ads/RewardedVideoAd;",
                        "Lcom/facebook/ads/RewardedAd;"
                },
                new String[]{ "show", "loadAd" },
                "V"));

        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{ "Lcom/unity3d/ads/UnityAds;" },
                new String[]{ "show", "load" },
                "V"));

        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/applovin/adview/AppLovinAdView;",
                        "Lcom/applovin/mediation/ads/MaxInterstitialAd;",
                        "Lcom/applovin/mediation/ads/MaxAdView;"
                },
                new String[]{ "showAd", "show", "loadAd", "load" },
                "V"));

        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{ "Lcom/ironsource/mediationsdk/IronSource;" },
                new String[]{ "showInterstitial", "showRewardedVideo" },
                "V"));

        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/mopub/mobileads/MoPubView;",
                        "Lcom/mopub/mobileads/MoPubInterstitial;"
                },
                new String[]{ "loadAd", "show" },
                "V"));

        /* ── Ads: Vungle / InMobi / Chartboost ─────────────────────────── */

        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/vungle/warren/Vungle;",
                        "Lcom/vungle/ads/InterstitialAd;"
                },
                new String[]{ "playAd", "show", "load" },
                "V"));

        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/inmobi/ads/InMobiBanner;",
                        "Lcom/inmobi/ads/InMobiInterstitial;"
                },
                new String[]{ "load", "show" },
                "V"));

        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{ "Lcom/chartboost/sdk/Chartboost;" },
                new String[]{ "showInterstitial", "showRewardedVideo" },
                "V"));

        /*
         * SSL pinning bypass (structural stubs).
         *
         *  - CertificatePinner.check -> void: pin verification no-ops.
         *  - OkHostnameVerifier.verify -> boolean TRUE (stubValue=1):
         *    hostname verification always passes. The value matters —
         *    stubbing it to false would reject every TLS handshake.
         */
        recipes.add(new Recipe(
                "SSL_BYPASS",
                new String[]{ "Lokhttp3/CertificatePinner;" },
                new String[]{ "check" },
                "V",
                0));

        recipes.add(new Recipe(
                "SSL_BYPASS",
                new String[]{ "Lokhttp3/internal/tls/OkHostnameVerifier;" },
                new String[]{ "verify" },
                "Z",
                1));

        /*
         * Root detection bypass — every verdict method stubbed to
         * boolean FALSE (stubValue=0) = "not rooted".
         */
        recipes.add(new Recipe(
                "ROOT_BYPASS",
                new String[]{ "Lcom/scottyab/rootbeer/RootBeer;" },
                new String[]{
                        "isRooted",
                        "isRootedWithoutBusyBoxCheck",
                        "detectRootManagementApps",
                        "detectPotentiallyDangerousApps",
                        "detectTestKeys",
                        "detectRootCloakingApps",
                        "checkForBusyBoxBinary"
                },
                "Z",
                0));

        /*
         * LICENSE_BYPASS — Play License Verification (LVL).
         * checkAccess/verify are the two classic nullification points:
         * void stubs mean the verdict callback never fires a denial.
         */
        recipes.add(new Recipe(
                "LICENSE_BYPASS",
                new String[]{ "Lcom/google/android/vending/licensing/LicenseChecker;" },
                new String[]{ "checkAccess" },
                "V"));

        recipes.add(new Recipe(
                "LICENSE_BYPASS",
                new String[]{ "Lcom/google/android/vending/licensing/LicenseValidator;" },
                new String[]{ "verify" },
                "V"));

        /*
         * IAP_BYPASS — Play Billing. The stub returns 0, which IS
         * BillingResponseCode.OK / BILLING_RESPONSE_RESULT_OK, so the
         * int stub is semantically the bypass verdict itself.
         */
        recipes.add(new Recipe(
                "IAP_BYPASS",
                new String[]{ "Lcom/android/billingclient/api/BillingResult;" },
                new String[]{ "getResponseCode" },
                "I",
                0));

        recipes.add(new Recipe(
                "IAP_BYPASS",
                new String[]{ "Lcom/android/billingclient/api/Purchase$PurchasesResult;" },
                new String[]{ "getResponseCode" },
                "I",
                0));

        recipes.add(new Recipe(
                "IAP_BYPASS",
                new String[]{ "Lcom/android/vending/billing/IInAppBillingService$Stub$Proxy;" },
                new String[]{ "isBillingSupported", "isBillingSupportedExtraParams" },
                "I",
                0));

        /*
         * GOOGLE_PLAY_BYPASS — availability gates. 0 == ConnectionResult
         * .SUCCESS, so the int stub reports Play Services as available.
         */
        recipes.add(new Recipe(
                "GOOGLE_PLAY_BYPASS",
                new String[]{
                        "Lcom/google/android/gms/common/GoogleApiAvailability;",
                        "Lcom/google/android/gms/common/GoogleApiAvailabilityLight;",
                        "Lcom/google/android/gms/common/GooglePlayServicesUtil;"
                },
                new String[]{ "isGooglePlayServicesAvailable" },
                "I",
                0));

        RECIPES = Collections.unmodifiableList(recipes);
    }

    /**
     * Exact-descriptor detectors, built generically from RECIPES.
     */
    private static final Map<String, List<String>> DETECTORS;

    static {
        Map<String, List<String>> detectors = new HashMap<>();

        for (Recipe recipe : RECIPES) {
            List<String> classes = detectors.get(recipe.key);

            if (classes == null) {
                classes = new ArrayList<>();
                detectors.put(recipe.key, classes);
            }

            Collections.addAll(classes, recipe.classes);
        }

        DETECTORS = Collections.unmodifiableMap(detectors);
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Parses and transforms a DEX.
     *
     * No silent fallback is performed. Every rejected transformation is an
     * exception; a method that cannot be proven safe is left untouched and
     * reported.
     */
    public static byte[] patch(
            byte[] dex,
            Set<String> patchKeys,
            Progress progress
    ) {
        if (dex == null) {
            throw new IllegalArgumentException("DEX input is null");
        }

        if (dex.length < HEADER_SIZE) {
            throw new IllegalArgumentException(
                    "DEX is smaller than the minimum header: " + dex.length
            );
        }

        if (patchKeys == null || patchKeys.isEmpty()) {
            /*
             * A no-op still validates. Silence must not hide malformed data.
             */
            new DexFile(dex).validate();
            return dex.clone();
        }

        DexFile file = new DexFile(dex);
        file.validate();

        byte[] out = dex.clone();

        log(progress, "DEX header validated");
        log(progress, "  file_size=" + file.fileSize);
        log(progress, "  string_ids_size=" + file.stringIdsSize);
        log(progress, "  type_ids_size=" + file.typeIdsSize);
        log(progress, "  proto_ids_size=" + file.protoIdsSize);
        log(progress, "  method_ids_size=" + file.methodIdsSize);
        log(progress, "  class_defs_size=" + file.classDefsSize);

        int patched = patchMethods(file, out, patchKeys, progress);

        if (patched == 0) {
            log(progress, "  no structural recipe matched");
            return dex.clone();
        }

        recomputeChecksums(out);

        /*
         * Re-parse the mutated result. Offsets and sizes are unchanged by
         * construction, but this catches any accidental structural damage
         * before the caller ever sees the bytes.
         */
        new DexFile(out).validate();

        log(progress, "  patched methods=" + patched);
        log(progress, "  DEX checksum/SHA-1 regenerated");

        return out;
    }

    /**
     * Conservative binary XML manifest transformer.
     *
     * Parses string pool, resource map and START_ELEMENT chunks, resolves
     * attribute names to resource IDs through the resource map, and touches
     * only requested attributes. No stride scans, no blind writes.
     */
    public static byte[] patchManifest(
            byte[] manifest,
            Set<String> patchKeys
    ) {
        if (manifest == null) {
            throw new IllegalArgumentException("Manifest is null");
        }

        if (manifest.length < 8) {
            throw new IllegalArgumentException("Manifest is too small");
        }

        if (patchKeys == null || patchKeys.isEmpty()) {
            return manifest.clone();
        }

        byte[] out = manifest.clone();

        StringPool pool = null;
        int resourceMapOffset = -1;

        int cursor = 0;

        while (cursor < out.length) {
            if (cursor + 8 > out.length) {
                throw new IllegalArgumentException(
                        "Truncated AXML chunk header at " + cursor
                );
            }

            int type = readU16(out, cursor);
            int headerSize = readU16(out, cursor + 2);
            int chunkSize = readU32Checked(out, cursor + 4);

            if (headerSize < 8 || chunkSize < headerSize) {
                throw new IllegalArgumentException(
                        "Invalid AXML chunk at " + cursor
                );
            }

            if ((long) cursor + chunkSize > out.length) {
                throw new IllegalArgumentException(
                        "AXML chunk exceeds file at " + cursor
                );
            }

            if (type == RES_STRING_POOL_TYPE) {
                pool = StringPool.parse(out, cursor);
            } else if (type == RES_XML_RESOURCE_MAP_TYPE) {
                resourceMapOffset = cursor;
            }

            cursor += chunkSize;
        }

        if (pool == null) {
            throw new IllegalArgumentException("AXML string pool not found");
        }

        if (resourceMapOffset < 0) {
            throw new IllegalArgumentException("AXML resource map not found");
        }

        boolean changed = false;

        cursor = 0;

        while (cursor < out.length) {
            if (cursor + 8 > out.length) {
                throw new IllegalArgumentException(
                        "Truncated AXML chunk header at " + cursor
                );
            }

            int type = readU16(out, cursor);
            int chunkSize = readU32Checked(out, cursor + 4);

            if (type == RES_XML_START_ELEMENT_TYPE) {
                changed |= patchStartElement(
                        out,
                        cursor,
                        chunkSize,
                        pool,
                        resourceMapOffset,
                        patchKeys
                );
            }

            cursor += chunkSize;
        }

        return changed ? out : manifest.clone();
    }

    /**
     * Kept for source compatibility with the current ApkEngine.
     */
    public static byte[] applyAdsDomainBlock(
            byte[] dex,
            List<String> domains
    ) {
        if (dex == null) {
            throw new IllegalArgumentException("DEX is null");
        }

        new DexFile(dex).validate();
        return dex.clone();
    }

    // -------------------------------------------------------------------------
    // Detection
    // -------------------------------------------------------------------------

    /**
     * Layer 1: exact descriptor presence in type_ids.
     * No substring matching, no byte scans.
     */
    public static Set<String> scanKeys(byte[] dex) {
        DexFile file = new DexFile(dex);
        file.validate();

        Set<String> descriptors = new HashSet<>();

        for (int i = 0; i < file.typeIdsSize; i++) {
            descriptors.add(file.getTypeDescriptor(i));
        }

        Set<String> keys = new HashSet<>();

        for (Map.Entry<String, List<String>> entry : DETECTORS.entrySet()) {
            for (String cls : entry.getValue()) {
                if (descriptors.contains(cls)) {
                    keys.add(entry.getKey());
                    break;
                }
            }
        }

        return keys;
    }

    /**
     * Layer 2: V8-compatible marker scan.
     *
     * SDK marker substrings anywhere in the DEX bytes. A hit means the
     * SDK is linked into the app and its patch is AVAILABLE — the patch
     * phase re-verifies structurally, so this can never cause corruption.
     */
    public static Set<String> scanMarkers(byte[] data) {
        Set<String> keys = new HashSet<>();

        for (String[] marker : MARKERS) {
            if (containsBytes(data, marker[1])) {
                keys.add(marker[0]);
            }
        }

        return keys;
    }

    private static boolean containsBytes(byte[] data, String needle) {
        byte[] pattern =
                needle.getBytes(StandardCharsets.US_ASCII);

        if (pattern.length == 0 || data.length < pattern.length) {
            return false;
        }

        byte first = pattern[0];
        int last = data.length - pattern.length;

        outer:
        for (int i = 0; i <= last; i++) {
            if (data[i] != first) {
                continue;
            }

            for (int j = 1; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    continue outer;
                }
            }

            return true;
        }

        return false;
    }

    public static List<String[]> quickScan(InputStream input) throws IOException {
        byte[] data = readAll(input);

        /*
         * Union of both detection layers:
         *   1. exact descriptor presence in type_ids (structural)
         *   2. SDK marker substrings anywhere in the DEX (V8-compatible)
         */
        Set<String> keys = scanKeys(data);
        keys.addAll(scanMarkers(data));

        List<String[]> result = new ArrayList<>();

        for (String key : keys) {
            result.add(new String[]{
                    key,
                    describeKey(key)
            });
        }

        return result;
    }

    private static String describeKey(String key) {
        switch (key) {
            case "REMOVE_ADS":
                return "Ad SDK entry points detected";
            case "DISABLE_ANALYTICS":
                return "Analytics SDK detected";
            case "REMOVE_TELEMETRY":
                return "Telemetry SDK detected";
            case "SSL_BYPASS":
                return "TLS pinning / trust manager detected";
            case "ROOT_BYPASS":
                return "Root detection detected";
            case "SAFETYNET_BYPASS":
                return "Integrity attestation detected";
            case "FRIDA_BYPASS":
                return "Frida / Xposed detection detected";
            case "LICENSE_BYPASS":
                return "Play Licensing detected";
            case "IAP_BYPASS":
                return "Play Billing detected";
            case "SIGNATURE_BYPASS":
                return "Signature check detected";
            case "GOOGLE_PLAY_BYPASS":
                return "Play Services availability gate detected";
            case "DISABLE_FLAG_SECURE":
                return "FLAG_SECURE usage detected";
            default:
                return "Detected";
        }
    }

    /**
     * Manifest-level detection. Only reports a patch when the attribute
     * EXISTS and its current value differs from the patch target.
     */
    public static Set<String> scanManifestKeys(byte[] manifest) {
        Set<String> keys = new HashSet<>();

        if (manifest == null || manifest.length < 8) {
            return keys;
        }

        StringPool pool = null;
        int resourceMapOffset = -1;

        int cursor = 0;

        while (cursor < manifest.length) {
            if (cursor + 8 > manifest.length) {
                return keys;
            }

            int type = readU16(manifest, cursor);
            int headerSize = readU16(manifest, cursor + 2);
            int chunkSize = readU32Checked(manifest, cursor + 4);

            if (headerSize < 8 || chunkSize < headerSize ||
                    (long) cursor + chunkSize > manifest.length) {
                return keys;
            }

            if (type == RES_STRING_POOL_TYPE && pool == null) {
                pool = StringPool.parse(manifest, cursor);
            } else if (type == RES_XML_RESOURCE_MAP_TYPE) {
                resourceMapOffset = cursor;
            }

            cursor += chunkSize;
        }

        if (pool == null || resourceMapOffset < 0) {
            return keys;
        }

        Boolean debuggable = null;
        Boolean allowBackup = null;
        Boolean fullBackupOnly = null;
        boolean exportedFalseFound = false;

        cursor = 0;

        while (cursor < manifest.length) {
            int type = readU16(manifest, cursor);
            int chunkSize = readU32Checked(manifest, cursor + 4);

            if (type == RES_XML_START_ELEMENT_TYPE &&
                    cursor + 36 <= manifest.length) {

                int nodeHeaderSize = readU16(manifest, cursor + 2);

                if (nodeHeaderSize >= 16 &&
                        cursor + nodeHeaderSize + 20 <= manifest.length) {

                    int ext = cursor + nodeHeaderSize;
                    int attributeStart = readU16(manifest, ext + 8);
                    int attributeSize = readU16(manifest, ext + 10);
                    int attributeCount = readU16(manifest, ext + 12);

                    if (attributeSize >= 20) {
                        int base = ext + attributeStart;

                        for (int i = 0; i < attributeCount; i++) {
                            if ((long) base + (long) (i + 1) * attributeSize >
                                    (long) cursor + chunkSize) {
                                break;
                            }

                            int attr = base + i * attributeSize;
                            int nameStringIndex =
                                    readU32Checked(manifest, attr + 4);

                            int resourceId = resolveResourceId(
                                    manifest,
                                    resourceMapOffset,
                                    nameStringIndex
                            );

                            int dataType =
                                    manifest[attr + 15] & 0xff;

                            Boolean value = null;

                            if (dataType == TYPE_INT_BOOLEAN) {
                                value = readU32Checked(manifest, attr + 16) != 0;
                            } else if (dataType == 0x03) {
                                /*
                                 * TYPE_STRING: compare the raw literal.
                                 */
                                String raw = poolString(
                                        pool,
                                        manifest,
                                        readU32Checked(manifest, attr + 16)
                                );

                                if (raw != null) {
                                    if ("true".equals(raw)) {
                                        value = Boolean.TRUE;
                                    } else if ("false".equals(raw)) {
                                        value = Boolean.FALSE;
                                    }
                                }
                            }

                            if (value == null) {
                                continue;
                            }

                            if (resourceId == ATTR_DEBUGGABLE) {
                                debuggable = value;
                            } else if (resourceId == ATTR_ALLOW_BACKUP) {
                                allowBackup = value;
                            } else if (resourceId == ATTR_FULL_BACKUP_ONLY) {
                                fullBackupOnly = value;
                            } else if (resourceId == ATTR_EXPORTED &&
                                    !value.booleanValue()) {
                                exportedFalseFound = true;
                            }
                        }
                    }
                }
            }

            cursor += chunkSize;
        }

        if (Boolean.FALSE.equals(debuggable)) {
            keys.add("FORCE_DEBUGGABLE");
        }

        if (Boolean.FALSE.equals(allowBackup) ||
                Boolean.TRUE.equals(fullBackupOnly)) {
            keys.add("ALLOW_BACKUP");
        }

        if (exportedFalseFound) {
            keys.add("EXPORT_ALL_COMPONENTS");
        }

        return keys;
    }

    private static String poolString(
            StringPool pool,
            byte[] data,
            int index
    ) {
        if (index < 0 || index >= pool.stringCount) {
            return null;
        }

        int abs = pool.chunkOffset +
                pool.stringsStart +
                pool.offsets[index];

        if (abs < 0 || abs + 2 > data.length) {
            return null;
        }

        try {
            if ((pool.flags & 0x100) != 0) {
                /*
                 * UTF-8 pool: MUTF-8 with ULEB128 length.
                 */
                return readMutf8(data, abs);
            }

            /*
             * UTF-16LE pool: u16 length, chars, NUL.
             */
            int len = readU16(data, abs);

            if (abs + 2 + len * 2 > data.length) {
                return null;
            }

            StringBuilder out = new StringBuilder(len);

            for (int i = 0; i < len; i++) {
                out.append((char) readU16(data, abs + 2 + i * 2));
            }

            return out.toString();
        } catch (RuntimeException e) {
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // DEX method analysis
    // -------------------------------------------------------------------------

    private static int patchMethods(
            DexFile file,
            byte[] out,
            Set<String> patchKeys,
            Progress progress
    ) {
        int patched = 0;

        for (int classIndex = 0; classIndex < file.classDefsSize; classIndex++) {
            int classDef = file.classDefsOff + classIndex * CLASS_DEF_SIZE;
            int classTypeIndex = file.readU32(classDef);
            String classDescriptor = file.getTypeDescriptor(classTypeIndex);
            int classDataOff = file.readU32(classDef + 24);

            if (classDataOff == 0) {
                continue;
            }

            checkRange(
                    classDataOff,
                    1,
                    out.length,
                    "class_data"
            );

            ClassData data = parseClassData(file, out, classDataOff);

            for (EncodedMethod method : data.methods) {
                if ((method.accessFlags & (ACC_NATIVE | ACC_ABSTRACT)) != 0) {
                    /*
                     * Native and abstract methods carry no code_item.
                     * Touching them is always corruption.
                     */
                    continue;
                }

                if (method.codeOffset == 0) {
                    continue;
                }

                if ((method.codeOffset & 3) != 0) {
                    throw new IllegalArgumentException(
                            "code_item offset is not 4-byte aligned: 0x" +
                                    Integer.toHexString(method.codeOffset) +
                                    " in " + classDescriptor
                    );
                }

                MethodInfo info = file.getMethodInfo(method.methodIndex);

                Recipe recipe = findRecipe(
                        patchKeys,
                        classDescriptor,
                        info.name
                );

                if (recipe == null) {
                    continue;
                }

                if (recipe.expectedReturnType != null &&
                        !recipe.expectedReturnType.equals(info.returnDescriptor)) {
                    continue;
                }

                CodeItem code = CodeItem.parse(out, method.codeOffset);

                if (code.triesSize != 0) {
                    /*
                     * Replacing a method containing try/catch regions
                     * without rebuilding the handler tables is unsafe.
                     */
                    log(
                            progress,
                            "  skip " + classDescriptor + "->" +
                                    info.name + ": tries_size != 0"
                    );
                    continue;
                }

                int requiredUnits = requiredCodeUnits(info.returnDescriptor);

                if (code.insnsSize < requiredUnits) {
                    log(
                            progress,
                            "  skip " + classDescriptor + "->" +
                                    info.name + ": insufficient insns_size"
                    );
                    continue;
                }

                emitReturnStub(
                        out,
                        code.insnsOffset,
                        code.insnsSize,
                        code.registersSize,
                        info.returnDescriptor,
                        recipe.stubValue
                );

                patched++;

                log(
                        progress,
                        "  patched " +
                                classDescriptor +
                                "->" +
                                info.name +
                                " " +
                                info.returnDescriptor
                );
            }
        }

        return patched;
    }

    private static Recipe findRecipe(
            Set<String> patchKeys,
            String classDescriptor,
            String methodName
    ) {
        for (Recipe recipe : RECIPES) {
            if (!patchKeys.contains(recipe.key)) {
                continue;
            }

            if (!recipe.matchesClass(classDescriptor)) {
                continue;
            }

            if (!recipe.matchesMethod(methodName)) {
                continue;
            }

            return recipe;
        }

        return null;
    }

    // -------------------------------------------------------------------------
    // Method code generation
    // -------------------------------------------------------------------------

    private static int requiredCodeUnits(String returnType) {
        if ("V".equals(returnType)) {
            return 1;
        }

        if ("J".equals(returnType) || "D".equals(returnType)) {
            return 3;
        }

        return 2;
    }

    private static void emitReturnStub(
            byte[] data,
            int offset,
            int insnsSize,
            int registersSize,
            String returnType,
            int stubValue
    ) {
        if (insnsSize <= 0) {
            throw new IllegalArgumentException("Invalid zero-length method");
        }

        /*
         * Fill the entire instruction stream with NOP first so no dead
         * original instructions survive behind the stub.
         */
        for (int i = 0; i < insnsSize * 2; i++) {
            data[offset + i] = 0;
        }

        if ("V".equals(returnType)) {
            /*
             * return-void => 0x000e
             */
            writeU16(data, offset, 0x000e);
            return;
        }

        if ("J".equals(returnType) || "D".equals(returnType)) {
            /*
             * const-wide/16 v0, #0 => 0x0016, literal 0x0000
             * return-wide v0 => 0x0010
             */
            if (registersSize < 2) {
                throw new IllegalArgumentException(
                        "Wide return requires 2 registers, method has " +
                                registersSize
                );
            }

            writeU16(data, offset, 0x0016);
            writeU16(data, offset + 2, 0x0000);
            writeU16(data, offset + 4, 0x0010);
            return;
        }

        if (registersSize < 1) {
            throw new IllegalArgumentException(
                    "Non-void return requires 1 register, method has " +
                            registersSize
            );
        }

        /*
         * const/4 v0, #literal — format 11n: opcode 0x12, register in A,
         * 4-bit signed literal in B (bits 8-11). stubValue 0 or 1 fits.
         * return v0 => 0x000f
         * return-object v0 => 0x0011 (object/array returns: null)
         */
        writeU16(data, offset, 0x0012 | ((stubValue & 0xF) << 8));
        writeU16(data, offset + 2, 0x000f);

        if (returnType.startsWith("L") || returnType.startsWith("[")) {
            writeU16(data, offset + 2, 0x0011);
        }
    }

    // -------------------------------------------------------------------------
    // Class data
    // -------------------------------------------------------------------------

    private static ClassData parseClassData(
            DexFile file,
            byte[] data,
            int offset
    ) {
        Cursor cursor = new Cursor(data, offset);

        int staticFields = cursor.readUleb128();
        int instanceFields = cursor.readUleb128();
        int directMethods = cursor.readUleb128();
        int virtualMethods = cursor.readUleb128();

        for (int i = 0; i < staticFields; i++) {
            cursor.readUleb128();
            cursor.readUleb128();
        }

        for (int i = 0; i < instanceFields; i++) {
            cursor.readUleb128();
            cursor.readUleb128();
        }

        List<EncodedMethod> methods = new ArrayList<>();

        int previousMethodIndex = 0;

        for (int i = 0; i < directMethods; i++) {
            int delta = cursor.readUleb128();
            int accessFlags = cursor.readUleb128();
            int codeOffset = cursor.readUleb128();

            previousMethodIndex += delta;

            methods.add(new EncodedMethod(
                    previousMethodIndex,
                    accessFlags,
                    codeOffset
            ));
        }

        previousMethodIndex = 0;

        for (int i = 0; i < virtualMethods; i++) {
            int delta = cursor.readUleb128();
            int accessFlags = cursor.readUleb128();
            int codeOffset = cursor.readUleb128();

            previousMethodIndex += delta;

            methods.add(new EncodedMethod(
                    previousMethodIndex,
                    accessFlags,
                    codeOffset
            ));
        }

        return new ClassData(methods);
    }

    // -------------------------------------------------------------------------
    // Binary XML
    // -------------------------------------------------------------------------

    private static boolean patchStartElement(
            byte[] data,
            int chunkOffset,
            int chunkSize,
            StringPool pool,
            int resourceMapOffset,
            Set<String> keys
    ) {
        /*
         * START_ELEMENT:
         *
         * ResXMLTree_node
         *   type u16
         *   headerSize u16
         *   size u32
         *   lineNumber u32
         *   comment u32
         *
         * ResXMLTree_attrExt (at nodeHeaderSize)
         *   ns u32
         *   name u32
         *   attributeStart u16
         *   attributeSize u16
         *   attributeCount u16
         *   idIndex u16
         *   classIndex u16
         *   styleIndex u16
         *
         * followed by attributeCount ResXMLTree_attribute entries.
         */
        if (chunkOffset + 36 > data.length) {
            throw new IllegalArgumentException("Truncated START_ELEMENT");
        }

        int nodeHeaderSize = readU16(data, chunkOffset + 2);

        if (nodeHeaderSize < 16) {
            throw new IllegalArgumentException(
                    "Invalid XML node header"
            );
        }

        int ext = chunkOffset + nodeHeaderSize;

        if (ext + 20 > data.length) {
            throw new IllegalArgumentException(
                    "Truncated START_ELEMENT extension"
            );
        }

        int attributeStart = readU16(data, ext + 8);
        int attributeSize = readU16(data, ext + 10);
        int attributeCount = readU16(data, ext + 12);

        if (attributeSize < 20) {
            throw new IllegalArgumentException(
                    "Unsupported AXML attribute size: " + attributeSize
            );
        }

        int attributesBase = ext + attributeStart;

        long end = (long) attributesBase +
                (long) attributeCount * attributeSize;

        if (attributesBase < 0 || end > chunkOffset + chunkSize ||
                end > data.length) {
            throw new IllegalArgumentException(
                    "START_ELEMENT attributes exceed chunk"
            );
        }

        boolean changed = false;

        for (int i = 0; i < attributeCount; i++) {
            int attr = attributesBase + i * attributeSize;
            int nameStringIndex = readU32Checked(data, attr + 4);

            int resourceId = resolveResourceId(
                    data,
                    resourceMapOffset,
                    nameStringIndex
            );

            if (resourceId == ATTR_DEBUGGABLE &&
                    keys.contains("FORCE_DEBUGGABLE")) {
                writeBooleanValue(data, attr, true);
                changed = true;
            }

            if (resourceId == ATTR_EXPORTED &&
                    keys.contains("EXPORT_ALL_COMPONENTS")) {
                writeBooleanValue(data, attr, true);
                changed = true;
            }

            if (resourceId == ATTR_ALLOW_BACKUP &&
                    keys.contains("ALLOW_BACKUP")) {
                writeBooleanValue(data, attr, true);
                changed = true;
            }

            if (resourceId == ATTR_FULL_BACKUP_ONLY &&
                    keys.contains("ALLOW_BACKUP")) {
                writeBooleanValue(data, attr, false);
                changed = true;
            }
        }

        return changed;
    }

    private static int resolveResourceId(
            byte[] data,
            int resourceMapOffset,
            int stringIndex
    ) {
        if (stringIndex < 0) {
            throw new IllegalArgumentException(
                    "Negative attribute name index: " + stringIndex
            );
        }

        int headerSize = readU16(data, resourceMapOffset + 2);
        int chunkSize = readU32Checked(data, resourceMapOffset + 4);
        int mapBase = resourceMapOffset + headerSize;

        long entryEnd = (long) mapBase +
                ((long) stringIndex + 1L) * 4L;

        if (entryEnd > resourceMapOffset + chunkSize ||
                entryEnd > data.length) {
            /*
             * This attribute name has no entry in the resource map —
             * it carries no Android resource ID. Reporting 0 means
             * "no match", which is correct, not an error.
             */
            return 0;
        }

        return readU32Checked(data, (int) (mapBase + (long) stringIndex * 4L));
    }

    private static void writeBooleanValue(
            byte[] data,
            int attributeOffset,
            boolean value
    ) {
        /*
         * Attribute:
         *   ns        +0
         *   name      +4
         *   rawValue  +8
         *   typedValue +12
         *
         * typedValue (Res_value):
         *   size     +0 (u16)
         *   res0     +2 (u8)
         *   dataType +3 (u8)
         *   data     +4 (u32)
         */
        writeU16(data, attributeOffset + 12, 8);
        data[attributeOffset + 14] = 0;
        data[attributeOffset + 15] = TYPE_INT_BOOLEAN;
        writeU32(
                data,
                attributeOffset + 16,
                value ? 1 : 0
        );
    }

    // -------------------------------------------------------------------------
    // DEX checksum
    // -------------------------------------------------------------------------

    public static void recomputeChecksums(byte[] dex) {
        if (dex.length < HEADER_SIZE) {
            throw new IllegalArgumentException("DEX too small");
        }

        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(
                    dex,
                    32,
                    dex.length - 32
            );

            byte[] digest = sha1.digest();

            System.arraycopy(
                    digest,
                    0,
                    dex,
                    12,
                    digest.length
            );

            Adler32 adler = new Adler32();
            adler.update(
                    dex,
                    12,
                    dex.length - 12
            );

            writeU32(
                    dex,
                    8,
                    (int) adler.getValue()
            );
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Unable to recompute DEX checksum",
                    e
            );
        }
    }

    // -------------------------------------------------------------------------
    // DEX file model
    // -------------------------------------------------------------------------

    private static final class DexFile {
        final byte[] bytes;
        final int fileSize;
        final int headerSize;
        final int stringIdsSize;
        final int stringIdsOff;
        final int typeIdsSize;
        final int typeIdsOff;
        final int protoIdsSize;
        final int protoIdsOff;
        final int methodIdsSize;
        final int methodIdsOff;
        final int classDefsSize;
        final int classDefsOff;
        final int dataSize;
        final int dataOff;

        DexFile(byte[] bytes) {
            this.bytes = bytes;
            fileSize = readCount(bytes, 0x20, "file_size");
            headerSize = readCount(bytes, 0x24, "header_size");
            stringIdsSize = readCount(bytes, 0x38, "string_ids_size");
            stringIdsOff = readCount(bytes, 0x3c, "string_ids_off");
            typeIdsSize = readCount(bytes, 0x40, "type_ids_size");
            typeIdsOff = readCount(bytes, 0x44, "type_ids_off");
            protoIdsSize = readCount(bytes, 0x48, "proto_ids_size");
            protoIdsOff = readCount(bytes, 0x4c, "proto_ids_off");
            methodIdsSize = readCount(bytes, 0x58, "method_ids_size");
            methodIdsOff = readCount(bytes, 0x5c, "method_ids_off");
            classDefsSize = readCount(bytes, 0x60, "class_defs_size");
            classDefsOff = readCount(bytes, 0x64, "class_defs_off");
            dataSize = readCount(bytes, 0x68, "data_size");
            dataOff = readCount(bytes, 0x6c, "data_off");
        }

        void validate() {
            if (bytes.length < HEADER_SIZE) {
                throw new IllegalArgumentException("DEX header truncated");
            }

            if (bytes[0] != 'd' ||
                    bytes[1] != 'e' ||
                    bytes[2] != 'x' ||
                    bytes[3] != '\n') {
                throw new IllegalArgumentException("Invalid DEX magic");
            }

            if (bytes[7] != 0) {
                throw new IllegalArgumentException("Invalid DEX magic terminator");
            }

            if (headerSize != HEADER_SIZE) {
                throw new IllegalArgumentException(
                        "Unsupported DEX header size: " + headerSize
                );
            }

            int endian = readU32Checked(bytes, 0x28);

            if (endian != DEX_ENDIAN_CONSTANT) {
                throw new IllegalArgumentException(
                        "Unsupported DEX endian tag: 0x" +
                                Integer.toHexString(endian)
                );
            }

            if (fileSize != bytes.length) {
                throw new IllegalArgumentException(
                        "DEX file_size mismatch: header=" +
                                fileSize +
                                " actual=" +
                                bytes.length
                );
            }

            if (dataOff < HEADER_SIZE ||
                    dataOff > bytes.length ||
                    (long) dataOff + dataSize > bytes.length) {
                throw new IllegalArgumentException(
                        "Invalid DEX data section"
                );
            }

            validateTable("string_ids", stringIdsSize, stringIdsOff, 4);
            validateTable("type_ids", typeIdsSize, typeIdsOff, TYPE_ID_SIZE);
            validateTable("proto_ids", protoIdsSize, protoIdsOff, PROTO_ID_SIZE);
            validateTable("method_ids", methodIdsSize, methodIdsOff, METHOD_ID_SIZE);
            validateTable("class_defs", classDefsSize, classDefsOff, CLASS_DEF_SIZE);
        }

        private void validateTable(
                String name,
                int count,
                int offset,
                int elementSize
        ) {
            if (count == 0) {
                if (offset != 0 &&
                        (offset < HEADER_SIZE || offset > bytes.length)) {
                    throw new IllegalArgumentException(
                            "Invalid empty " + name + " offset"
                    );
                }
                return;
            }

            if (offset < HEADER_SIZE) {
                throw new IllegalArgumentException(
                        name + " offset points inside header"
                );
            }

            long end =
                    (long) offset +
                            (long) count * elementSize;

            if (end > bytes.length) {
                throw new IllegalArgumentException(
                        name + " table exceeds file: end=" + end +
                                " file=" + bytes.length
                );
            }

            if ((offset & 3) != 0) {
                throw new IllegalArgumentException(
                        name + " offset is not 4-byte aligned"
                );
            }
        }

        int readU32(int offset) {
            return readU32Checked(bytes, offset);
        }

        String getString(int index) {
            if (index < 0 || index >= stringIdsSize) {
                throw new IllegalArgumentException(
                        "string index out of range: " + index
                );
            }

            int stringOffset = readU32(
                    stringIdsOff + index * 4
            );

            checkRange(
                    stringOffset,
                    1,
                    bytes.length,
                    "string_data"
            );

            return readMutf8(bytes, stringOffset);
        }

        String getTypeDescriptor(int typeIndex) {
            if (typeIndex < 0 || typeIndex >= typeIdsSize) {
                throw new IllegalArgumentException(
                        "type index out of range: " + typeIndex
                );
            }

            int descriptorIndex =
                    readU32(typeIdsOff + typeIndex * 4);

            return getString(descriptorIndex);
        }

        MethodInfo getMethodInfo(int methodIndex) {
            if (methodIndex < 0 || methodIndex >= methodIdsSize) {
                throw new IllegalArgumentException(
                        "method index out of range: " + methodIndex
                );
            }

            int offset =
                    methodIdsOff +
                            methodIndex * METHOD_ID_SIZE;

            int classIndex = readU16(bytes, offset);
            int protoIndex = readU16(bytes, offset + 2);
            int nameIndex = readU32(offset + 4);

            String name = getString(nameIndex);

            if (protoIndex < 0 ||
                    protoIndex >= protoIdsSize) {
                throw new IllegalArgumentException(
                        "proto index out of range: " + protoIndex
                );
            }

            int protoOffset =
                    protoIdsOff +
                            protoIndex * PROTO_ID_SIZE;

            /*
             * proto_id_struct:
             *   shorty_idx       u32 @ +0
             *   return_type_idx  u32 @ +4
             *   parameters_off   u32 @ +8
             */
            int shortyIndex = readU32(protoOffset);
            int returnTypeIndex = readU32(protoOffset + 4);

            String returnDescriptor =
                    getTypeDescriptor(returnTypeIndex);

            String shorty = getString(shortyIndex);

            if (shorty.isEmpty()) {
                throw new IllegalArgumentException(
                        "Empty proto shorty at index " + shortyIndex
                );
            }

            verifyShortyAgainstReturn(shorty.charAt(0), returnDescriptor);

            return new MethodInfo(
                    methodIndex,
                    classIndex,
                    protoIndex,
                    name,
                    returnDescriptor
            );
        }

        private void verifyShortyAgainstReturn(
                char shortyFirst,
                String returnDescriptor
        ) {
            boolean ok;

            switch (shortyFirst) {
                case 'V':
                    ok = "V".equals(returnDescriptor);
                    break;
                case 'J':
                    ok = "J".equals(returnDescriptor);
                    break;
                case 'D':
                    ok = "D".equals(returnDescriptor);
                    break;
                case 'Z':
                case 'B':
                case 'S':
                case 'C':
                case 'I':
                case 'F':
                    ok = returnDescriptor.equals(
                            String.valueOf(shortyFirst)
                    );
                    break;
                case 'L':
                    /*
                     * Shorty 'L' covers both object and array returns.
                     */
                    ok = returnDescriptor.startsWith("L") ||
                            returnDescriptor.startsWith("[");
                    break;
                default:
                    ok = false;
                    break;
            }

            if (!ok) {
                throw new IllegalArgumentException(
                        "proto shorty/return mismatch: shorty='" +
                                shortyFirst +
                                "' return=" +
                                returnDescriptor
                );
            }
        }
    }

    // -------------------------------------------------------------------------
    // MUTF-8 (strict)
    // -------------------------------------------------------------------------

    private static String readMutf8(
            byte[] data,
            int offset
    ) {
        Cursor cursor = new Cursor(data, offset);

        int declaredUtf16Length =
                cursor.readUleb128();

        if (declaredUtf16Length < 0) {
            throw new IllegalArgumentException(
                    "Negative declared string length"
            );
        }

        StringBuilder out =
                new StringBuilder(declaredUtf16Length);

        boolean terminated = false;

        while (cursor.position < data.length) {
            int b = data[cursor.position++] & 0xff;

            if (b == 0) {
                terminated = true;
                break;
            }

            if ((b & 0x80) == 0) {
                out.append((char) b);
                continue;
            }

            if (b == 0xC0) {
                /*
                 * MUTF-8 encodes U+0000 as 0xC0 0x80. Any other 0xC0
                 * pair is an overlong encoding and must be rejected.
                 */
                requireBytes(cursor, 1);

                int b2 = data[cursor.position++] & 0xff;

                if (b2 == 0x80) {
                    out.append('\u0000');
                } else {
                    throw new IllegalArgumentException(
                            String.format(
                                    "Overlong MUTF-8 sequence C0 %02X",
                                    b2
                            )
                    );
                }
                continue;
            }

            if (b == 0xC1) {
                throw new IllegalArgumentException(
                        "Overlong MUTF-8 leading byte C1"
                );
            }

            if ((b & 0xE0) == 0xC0) {
                /*
                 * 0xC2..0xDF: legal two-byte sequences.
                 */
                requireBytes(cursor, 1);

                int b2 = data[cursor.position++] & 0xff;

                if ((b2 & 0xC0) != 0x80) {
                    throw new IllegalArgumentException(
                            "Invalid MUTF-8 continuation byte"
                    );
                }

                int value =
                        ((b & 0x1F) << 6) |
                                (b2 & 0x3F);

                if (value < 0x80) {
                    throw new IllegalArgumentException(
                            "Overlong MUTF-8 two-byte sequence"
                    );
                }

                out.append((char) value);
                continue;
            }

            if ((b & 0xF0) == 0xE0) {
                /*
                 * Three-byte sequences. Lone surrogates (0xED A0..BF)
                 * are legal MUTF-8: supplementary characters are stored
                 * as UTF-16 surrogate pairs.
                 */
                requireBytes(cursor, 2);

                int b2 = data[cursor.position++] & 0xff;
                int b3 = data[cursor.position++] & 0xff;

                if ((b2 & 0xC0) != 0x80 ||
                        (b3 & 0xC0) != 0x80) {
                    throw new IllegalArgumentException(
                            "Invalid MUTF-8 sequence"
                    );
                }

                if (b == 0xE0 && b2 < 0xA0) {
                    throw new IllegalArgumentException(
                            String.format(
                                    "Overlong MUTF-8 sequence E0 %02X",
                                    b2
                            )
                    );
                }

                int value =
                        ((b & 0x0F) << 12) |
                                ((b2 & 0x3F) << 6) |
                                (b3 & 0x3F);

                out.append((char) value);
                continue;
            }

            /*
             * 0xF0..0xFF never appear in MUTF-8.
             */
            throw new IllegalArgumentException(
                    "Unsupported MUTF-8 leading byte 0x" +
                            Integer.toHexString(b)
            );
        }

        if (!terminated) {
            throw new IllegalArgumentException(
                    "DEX string has no NUL terminator"
            );
        }

        if (out.length() != declaredUtf16Length) {
            throw new IllegalArgumentException(
                    "DEX string length mismatch: declared=" +
                            declaredUtf16Length +
                            " actual=" +
                            out.length()
            );
        }

        return out.toString();
    }

    private static void requireBytes(
            Cursor cursor,
            int count
    ) {
        if (cursor.position + count > cursor.data.length) {
            throw new IllegalArgumentException(
                    "Truncated MUTF-8 string"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Code item
    // -------------------------------------------------------------------------

    private static final class CodeItem {
        final int registersSize;
        final int insSize;
        final int outsSize;
        final int triesSize;
        final int insnsSize;
        final int insnsOffset;

        private CodeItem(
                int registersSize,
                int insSize,
                int outsSize,
                int triesSize,
                int insnsSize,
                int insnsOffset
        ) {
            this.registersSize = registersSize;
            this.insSize = insSize;
            this.outsSize = outsSize;
            this.triesSize = triesSize;
            this.insnsSize = insnsSize;
            this.insnsOffset = insnsOffset;
        }

        static CodeItem parse(
                byte[] data,
                int offset
        ) {
            checkRange(
                    offset,
                    16,
                    data.length,
                    "code_item"
            );

            if ((offset & 3) != 0) {
                throw new IllegalArgumentException(
                        "code_item is not 4-byte aligned: 0x" +
                                Integer.toHexString(offset)
                );
            }

            int registersSize =
                    readU16(data, offset);
            int insSize =
                    readU16(data, offset + 2);
            int outsSize =
                    readU16(data, offset + 4);
            int triesSize =
                    readU16(data, offset + 6);
            int insnsSize =
                    readU32Checked(data, offset + 12);

            if (insSize < 0 || insSize > registersSize) {
                throw new IllegalArgumentException(
                        "code_item ins_size=" + insSize +
                                " exceeds registers_size=" + registersSize
                );
            }

            if (insnsSize < 0) {
                throw new IllegalArgumentException(
                        "code_item insns_size is negative: " + insnsSize
                );
            }

            int insnsOffset = offset + 16;

            long end =
                    (long) insnsOffset +
                            (long) insnsSize * 2L;

            if (end > data.length) {
                throw new IllegalArgumentException(
                        "code_item instructions exceed DEX"
                );
            }

            return new CodeItem(
                    registersSize,
                    insSize,
                    outsSize,
                    triesSize,
                    insnsSize,
                    insnsOffset
            );
        }
    }

    // -------------------------------------------------------------------------
    // Recipe / model
    // -------------------------------------------------------------------------

    private static final class Recipe {
        final String key;
        final String[] classes;
        final String[] methods;
        final String expectedReturnType;
        final int stubValue;

        Recipe(
                String key,
                String[] classes,
                String[] methods,
                String expectedReturnType
        ) {
            this(key, classes, methods, expectedReturnType, 0);
        }

        Recipe(
                String key,
                String[] classes,
                String[] methods,
                String expectedReturnType,
                int stubValue
        ) {
            this.key = key;
            this.classes = classes;
            this.methods = methods;
            this.expectedReturnType = expectedReturnType;
            this.stubValue = stubValue;
        }

        boolean matchesClass(String descriptor) {
            for (String candidate : classes) {
                if (candidate.equals(descriptor)) {
                    return true;
                }
            }
            return false;
        }

        boolean matchesMethod(String name) {
            for (String candidate : methods) {
                if (candidate.equals(name)) {
                    return true;
                }
            }
            return false;
        }
    }

    private static final class MethodInfo {
        final int methodIndex;
        final int classIndex;
        final int protoIndex;
        final String name;
        final String returnDescriptor;

        MethodInfo(
                int methodIndex,
                int classIndex,
                int protoIndex,
                String name,
                String returnDescriptor
        ) {
            this.methodIndex = methodIndex;
            this.classIndex = classIndex;
            this.protoIndex = protoIndex;
            this.name = name;
            this.returnDescriptor = returnDescriptor;
        }
    }

    private static final class EncodedMethod {
        final int methodIndex;
        final int accessFlags;
        final int codeOffset;

        EncodedMethod(
                int methodIndex,
                int accessFlags,
                int codeOffset
        ) {
            this.methodIndex = methodIndex;
            this.accessFlags = accessFlags;
            this.codeOffset = codeOffset;
        }
    }

    private static final class ClassData {
        final List<EncodedMethod> methods;

        ClassData(List<EncodedMethod> methods) {
            this.methods = methods;
        }
    }

    private static final class Cursor {
        final byte[] data;
        int position;

        Cursor(byte[] data, int position) {
            this.data = data;
            this.position = position;
        }

        int readUleb128() {
            int result = 0;
            int shift = 0;

            for (int i = 0; i < 5; i++) {
                if (position >= data.length) {
                    throw new IllegalArgumentException(
                            "Truncated ULEB128"
                    );
                }

                int b = data[position++] & 0xff;

                result |=
                        (b & 0x7f) << shift;

                if ((b & 0x80) == 0) {
                    return result;
                }

                shift += 7;
            }

            throw new IllegalArgumentException(
                    "ULEB128 exceeds 5 bytes"
            );
        }
    }

    // -------------------------------------------------------------------------
    // String pool parser for AXML
    // -------------------------------------------------------------------------

    private static final class StringPool {
        final int chunkOffset;
        final int chunkSize;
        final int stringCount;
        final int flags;
        final int stringsStart;
        final int[] offsets;

        private StringPool(
                int chunkOffset,
                int chunkSize,
                int stringCount,
                int flags,
                int stringsStart,
                int[] offsets
        ) {
            this.chunkOffset = chunkOffset;
            this.chunkSize = chunkSize;
            this.stringCount = stringCount;
            this.flags = flags;
            this.stringsStart = stringsStart;
            this.offsets = offsets;
        }

        static StringPool parse(
                byte[] data,
                int offset
        ) {
            int headerSize =
                    readU16(data, offset + 2);
            int chunkSize =
                    readU32Checked(data, offset + 4);
            int stringCount =
                    readU32Checked(data, offset + 8);
            int flags =
                    readU32Checked(data, offset + 16);
            int stringsStart =
                    readU32Checked(data, offset + 20);

            if (headerSize < 28) {
                throw new IllegalArgumentException(
                        "Invalid string pool header"
                );
            }

            if (stringCount < 0) {
                throw new IllegalArgumentException(
                        "Invalid string count"
                );
            }

            int[] offsets =
                    new int[stringCount];

            int offsetBase =
                    offset + headerSize;

            long offsetsEnd =
                    (long) offsetBase +
                            (long) stringCount * 4L;

            if (offsetsEnd > offset + chunkSize ||
                    offsetsEnd > data.length) {
                throw new IllegalArgumentException(
                        "String pool offsets exceed chunk"
                );
            }

            for (int i = 0; i < stringCount; i++) {
                offsets[i] =
                        readU32Checked(
                                data,
                                offsetBase + i * 4
                        );
            }

            return new StringPool(
                    offset,
                    chunkSize,
                    stringCount,
                    flags,
                    stringsStart,
                    offsets
            );
        }
    }

    // -------------------------------------------------------------------------
    // Binary helpers
    // -------------------------------------------------------------------------

    private static int readCount(
            byte[] data,
            int offset,
            String what
    ) {
        int value = readU32Checked(data, offset);

        if (value < 0) {
            throw new IllegalArgumentException(
                    what + " is negative: " + (value & 0xFFFFFFFFL)
            );
        }

        return value;
    }

    private static int readU16(
            byte[] data,
            int offset
    ) {
        checkRange(
                offset,
                2,
                data.length,
                "u16"
        );

        return
                (data[offset] & 0xff) |
                        ((data[offset + 1] & 0xff) << 8);
    }

    private static int readU32Checked(
            byte[] data,
            int offset
    ) {
        checkRange(
                offset,
                4,
                data.length,
                "u32"
        );

        return
                (data[offset] & 0xff) |
                        ((data[offset + 1] & 0xff) << 8) |
                        ((data[offset + 2] & 0xff) << 16) |
                        ((data[offset + 3] & 0xff) << 24);
    }

    private static void writeU16(
            byte[] data,
            int offset,
            int value
    ) {
        checkRange(
                offset,
                2,
                data.length,
                "u16 write"
        );

        data[offset] = (byte) value;
        data[offset + 1] = (byte) (value >>> 8);
    }

    private static void writeU32(
            byte[] data,
            int offset,
            int value
    ) {
        checkRange(
                offset,
                4,
                data.length,
                "u32 write"
        );

        data[offset] = (byte) value;
        data[offset + 1] = (byte) (value >>> 8);
        data[offset + 2] = (byte) (value >>> 16);
        data[offset + 3] = (byte) (value >>> 24);
    }

    private static void checkRange(
            int offset,
            int length,
            int total,
            String what
    ) {
        if (offset < 0 ||
                length < 0 ||
                (long) offset + length > total) {
            throw new IllegalArgumentException(
                    "Invalid " + what +
                            " range: offset=" +
                            offset +
                            " length=" +
                            length +
                            " total=" +
                            total
            );
        }
    }

    private static byte[] readAll(
            InputStream input
    ) throws IOException {
        ByteArrayOutputStream out =
                new ByteArrayOutputStream();

        byte[] buffer = new byte[64 * 1024];
        int n;

        while ((n = input.read(buffer)) != -1) {
            out.write(buffer, 0, n);
        }

        return out.toByteArray();
    }

    private static void log(
            Progress progress,
            String message
    ) {
        if (progress != null) {
            progress.log(message);
        }
    }
}
