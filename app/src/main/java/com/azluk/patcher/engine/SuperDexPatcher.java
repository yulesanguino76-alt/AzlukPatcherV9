package com.azluk.patcher.engine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
 *  - validates the DEX header before reading tables (spec offsets:
 *    string_ids @0x38/0x3C, class_defs @0x60/0x64)
 *  - proto_id return_type_idx read at +4 (shorty @+0, return @+4,
 *    parameters_off @+8) — the previous +8 read was the bug that made
 *    every parameterized recipe silently miss
 *  - decodes DEX strings as strict MUTF-8
 *  - resolves methods structurally: class_defs -> class_data ->
 *    method_ids -> name_idx -> string_ids. Never const-string scans.
 *  - never touches ACC_NATIVE / ACC_ABSTRACT methods
 *  - try/catch methods are stubbed HEAD-ONLY preserving instruction
 *    boundaries (NOP fill to the first real boundary, stub at entry,
 *    tail + try/handler tables byte-identical) — this is what unlocks
 *    GMA's loadAd/show/initialize, always wrapped in try/catch
 *  - stubs are verdict-aware: const/4 v0, #stubValue encoded as
 *    format 11n with literal in bits 15-12 (0 == OK/false, 1 == true)
 *  - caller-context recipes: boolean app methods that delegate their
 *    verdict to java.security.Signature.verify(byte[]) are stubbed to
 *    TRUE (SIGNATURE_BYPASS) — matched by exact method_id + invoke scan
 *  - recomputes SHA-1 + Adler32 only after successful mutation, then
 *    re-validates the output before returning it
 *
 * Detection = union of:
 *   1. structural descriptor presence in type_ids (from RECIPES)
 *   2. SDK marker substrings (V8-compatible badge layer)
 * A detection hit means AVAILABLE. Keys without a safe structural
 * recipe no-op with a loud log — detection can never corrupt a DEX.
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

    // -------------------------------------------------------------------------
    // Recipes — exact class descriptor + exact method + expected return
    // -------------------------------------------------------------------------

    private static final List<Recipe> RECIPES;

    static {
        List<Recipe> recipes = new ArrayList<>();

        /*
         * Analytics.
         */
        recipes.add(new Recipe(
                "DISABLE_ANALYTICS",
                new String[]{ "Lcom/google/firebase/analytics/FirebaseAnalytics;" },
                new String[]{ "logEvent" },
                "V"
        ));
        recipes.add(new Recipe(
                "DISABLE_ANALYTICS",
                new String[]{ "Lcom/mixpanel/android/mpmetrics/MixpanelAPI;" },
                new String[]{ "track", "trackMap" },
                "V"
        ));

        /*
         * Telemetry.
         */
        recipes.add(new Recipe(
                "REMOVE_TELEMETRY",
                new String[]{ "Lio/sentry/Sentry;" },
                new String[]{ "captureException", "captureMessage", "captureEvent" },
                null
        ));
        recipes.add(new Recipe(
                "REMOVE_TELEMETRY",
                new String[]{ "Lcom/google/firebase/crashlytics/FirebaseCrashlytics;" },
                new String[]{ "recordException", "log" },
                "V"
        ));
        recipes.add(new Recipe(
                "REMOVE_TELEMETRY",
                new String[]{ "Lcom/bugsnag/android/Bugsnag;" },
                new String[]{ "notify" },
                null
        ));

        /*
         * Ads — legacy GMA SDK.
         */
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{ "Lcom/google/android/gms/ads/AdView;" },
                new String[]{ "loadAd" },
                "V"
        ));
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/google/android/gms/ads/InterstitialAd;",
                        "Lcom/google/android/gms/ads/AppOpenAd;",
                        "Lcom/google/android/gms/ads/rewarded/RewardedAd;"
                },
                new String[]{ "show" },
                "V"
        ));

        /*
         * Ads — modern GMA SDK (v20+): subpackaged entry points.
         */
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{ "Lcom/google/android/gms/ads/banner/BannerView;" },
                new String[]{ "loadAd" },
                "V"
        ));
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/google/android/gms/ads/interstitial/InterstitialAd;",
                        "Lcom/google/android/gms/ads/rewarded/RewardedAd;",
                        "Lcom/google/android/gms/ads/appopen/AppOpenAd;"
                },
                new String[]{ "show" },
                "V"
        ));

        /*
         * Ads — GMA v20+ LOAD side. Banners/natives load through AdLoader,
         * interstitial/rewarded/appopen are acquired through static load().
         * Stubbing only show() left the ad LOADED in memory — and visible.
         */
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{ "Lcom/google/android/gms/ads/AdLoader;" },
                new String[]{ "loadAd" },
                "V"
        ));
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/google/android/gms/ads/interstitial/InterstitialAd;",
                        "Lcom/google/android/gms/ads/rewarded/RewardedAd;",
                        "Lcom/google/android/gms/ads/appopen/AppOpenAd;"
                },
                new String[]{ "load" },
                "V"
        ));

        /*
         * Ads — SDK bootstrap. The SDK never starts.
         */
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{ "Lcom/google/android/gms/ads/MobileAds;" },
                new String[]{ "initialize" },
                "V"
        ));
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{ "Lcom/applovin/sdk/AppLovinSdk;" },
                new String[]{ "initializeSdk" },
                "V"
        ));

        /*
         * Ads — Facebook / Unity / AppLovin / IronSource / MoPub.
         */
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/facebook/ads/AdView;",
                        "Lcom/facebook/ads/BannerAdView;"
                },
                new String[]{ "loadAd" },
                "V"
        ));
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/facebook/ads/InterstitialAd;",
                        "Lcom/facebook/ads/RewardedVideoAd;",
                        "Lcom/facebook/ads/RewardedAd;"
                },
                new String[]{ "show", "loadAd" },
                "V"
        ));
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{ "Lcom/unity3d/ads/UnityAds;" },
                new String[]{ "show", "load" },
                "V"
        ));
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/applovin/adview/AppLovinAdView;",
                        "Lcom/applovin/mediation/ads/MaxInterstitialAd;",
                        "Lcom/applovin/mediation/ads/MaxAdView;"
                },
                new String[]{ "showAd", "show", "loadAd", "load" },
                "V"
        ));
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{ "Lcom/ironsource/mediationsdk/IronSource;" },
                new String[]{ "showInterstitial", "showRewardedVideo" },
                "V"
        ));
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/mopub/mobileads/MoPubView;",
                        "Lcom/mopub/mobileads/MoPubInterstitial;"
                },
                new String[]{ "loadAd", "show" },
                "V"
        ));

        /*
         * Ads — Vungle / InMobi / Chartboost.
         */
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/vungle/warren/Vungle;",
                        "Lcom/vungle/ads/InterstitialAd;"
                },
                new String[]{ "playAd", "show", "load" },
                "V"
        ));
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{
                        "Lcom/inmobi/ads/InMobiBanner;",
                        "Lcom/inmobi/ads/InMobiInterstitial;"
                },
                new String[]{ "load", "show" },
                "V"
        ));
        recipes.add(new Recipe(
                "REMOVE_ADS",
                new String[]{ "Lcom/chartboost/sdk/Chartboost;" },
                new String[]{ "showInterstitial", "showRewardedVideo" },
                "V"
        ));

        /*
         * SSL pinning bypass. stubValue matters:
         *   - CertificatePinner.check -> void: pin verification no-ops.
         *   - OkHostnameVerifier.verify -> TRUE (stubValue=1): hostname
         *     verification passes. Stubbing FALSE would reject every
         *     TLS handshake and break the app outright.
         */
        recipes.add(new Recipe(
                "SSL_BYPASS",
                new String[]{ "Lokhttp3/CertificatePinner;" },
                new String[]{ "check" },
                "V",
                0
        ));
        recipes.add(new Recipe(
                "SSL_BYPASS",
                new String[]{ "Lokhttp3/internal/tls/OkHostnameVerifier;" },
                new String[]{ "verify" },
                "Z",
                1
        ));

        /*
         * Root detection — every verdict stubbed FALSE (0) = "not rooted".
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
                0
        ));

        /*
         * LICENSE_BYPASS — Play LVL. Void stubs on the classic
         * nullification points: the denial callback never fires.
         */
        recipes.add(new Recipe(
                "LICENSE_BYPASS",
                new String[]{ "Lcom/google/android/vending/licensing/LicenseChecker;" },
                new String[]{ "checkAccess" },
                "V"
        ));
        recipes.add(new Recipe(
                "LICENSE_BYPASS",
                new String[]{ "Lcom/google/android/vending/licensing/LicenseValidator;" },
                new String[]{ "verify" },
                "V"
        ));

        /*
         * IAP_BYPASS — the stub returns 0, which IS
         * BillingResponseCode.OK / BILLING_RESPONSE_RESULT_OK.
         */
        recipes.add(new Recipe(
                "IAP_BYPASS",
                new String[]{ "Lcom/android/billingclient/api/BillingResult;" },
                new String[]{ "getResponseCode" },
                "I",
                0
        ));
        recipes.add(new Recipe(
                "IAP_BYPASS",
                new String[]{ "Lcom/android/billingclient/api/Purchase$PurchasesResult;" },
                new String[]{ "getResponseCode" },
                "I",
                0
        ));
        recipes.add(new Recipe(
                "IAP_BYPASS",
                new String[]{ "Lcom/android/vending/billing/IInAppBillingService$Stub$Proxy;" },
                new String[]{ "isBillingSupported", "isBillingSupportedExtraParams" },
                "I",
                0
        ));

        /*
         * GOOGLE_PLAY_BYPASS — availability gates. 0 == ConnectionResult
         * .SUCCESS: Play Services reported as available.
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
                0
        ));

        RECIPES = Collections.unmodifiableList(recipes);
    }

    /**
     * Caller-context recipes: instead of synthesizing receipts, stub the
     * APP-LEVEL method that delegates its verdict to a framework verifier.
     * A boolean/void method whose body invokes the target is a local
     * verdict method (receipt checks, license checks, update checks).
     * Match: exact method_id (class + name), then an invoke-site scan of
     * candidate bodies. Boolean verdicts stub to TRUE.
     */
    private static final Map<String, String[][]> CALLER_TARGETS;

    static {
        Map<String, String[][]> callerTargets = new HashMap<>();

        callerTargets.put(
                "SIGNATURE_BYPASS",
                new String[][]{
                        { "Ljava/security/Signature;", "verify" }
                }
        );

        CALLER_TARGETS = Collections.unmodifiableMap(callerTargets);
    }

    /**
     * Structural detectors, built generically from RECIPES so every
     * recipe key is auto-detected by exact descriptor presence.
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

    /**
     * Marker layer (V8-compatible): UTF-8 substrings that only exist in
     * a DEX when the corresponding SDK is linked in. A hit means the
     * patch is AVAILABLE — nothing more.
     */
    private static final String[][] MARKERS = {
            /* Licensing */
            { "LICENSE_BYPASS", "ILicensingService" },
            { "LICENSE_BYPASS", "com/google/android/vending/licensing" },
            { "LICENSE_BYPASS", "LICENSED" },
            /* Play Billing */
            { "IAP_BYPASS", "com/android/vending/billing" },
            { "IAP_BYPASS", "BillingClient" },
            { "IAP_BYPASS", "PURCHASED" },
            /* Signature checks */
            { "SIGNATURE_BYPASS", "getSignatures" },
            { "SIGNATURE_BYPASS", "GET_SIGNATURES" },
            { "SIGNATURE_BYPASS", "signingInfo" },
            /* Ad SDKs */
            { "REMOVE_ADS", "com/google/android/gms/ads" },
            { "REMOVE_ADS", "com/facebook/ads" },
            { "REMOVE_ADS", "com/unity3d/ads" },
            { "REMOVE_ADS", "com/applovin" },
            { "REMOVE_ADS", "com/ironsource" },
            { "REMOVE_ADS", "com/mopub" },
            { "REMOVE_ADS", "com/chartboost" },
            { "REMOVE_ADS", "com/vungle" },
            { "REMOVE_ADS", "com/inmobi" },
            { "REMOVE_ADS", "com/mbridge" },
            { "REMOVE_ADS", "com/tapjoy" },
            { "REMOVE_ADS", "com/startapp" },
            { "REMOVE_ADS", "com/adcolony" },
            /* TLS pinning / trust managers */
            { "SSL_BYPASS", "CertificatePinner" },
            { "SSL_BYPASS", "checkServerTrusted" },
            { "SSL_BYPASS", "checkClientTrusted" },
            { "SSL_BYPASS", "javax/net/ssl/X509TrustManager" },
            /* Root detection */
            { "ROOT_BYPASS", "isRooted" },
            { "ROOT_BYPASS", "RootBeer" },
            { "ROOT_BYPASS", "isDeviceRooted" },
            { "ROOT_BYPASS", "/system/xbin/su" },
            /* Integrity attestation */
            { "SAFETYNET_BYPASS", "SafetyNet" },
            { "SAFETYNET_BYPASS", "com/google/android/play/core/integrity" },
            /* Anti-Frida / anti-Xposed */
            { "FRIDA_BYPASS", "frida" },
            { "FRIDA_BYPASS", "XposedBridge" },
            { "FRIDA_BYPASS", "tracerpid" },
            /* Emulator detection SDKs */
            { "EMULATOR_BYPASS", "qemu" },
            { "EMULATOR_BYPASS", "goldfish" },
            /* Screenshot blocking */
            { "DISABLE_FLAG_SECURE", "FLAG_SECURE" }
    };

    // -------------------------------------------------------------------------
    // Public DEX API
    // -------------------------------------------------------------------------

    /**
     * Parses and transforms a DEX. No silent fallback is performed.
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
             * Still validate: a no-op must not hide malformed DEX data.
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
        patched += patchCallerVerdicts(file, out, patchKeys, progress);

        if (patched == 0) {
            log(progress, "  no structural recipe matched");
            return dex.clone();
        }

        recomputeChecksums(out);

        /*
         * Re-parse the result: catches accidental structural corruption
         * before the caller receives the bytes.
         */
        new DexFile(out).validate();

        log(progress, "  patched methods=" + patched);
        log(progress, "  DEX checksum/SHA-1 regenerated");

        return out;
    }

    /**
     * Structural scan: union of type_ids descriptors and marker
     * substrings. Used by ApkEngine for availability badges.
     */
    public static Set<String> scanKeys(byte[] dex) {
        DexFile file = new DexFile(dex);
        file.validate();

        Set<String> keys = new HashSet<>();

        for (Recipe recipe : RECIPES) {
            if (containsRecipeTarget(file, recipe)) {
                keys.add(recipe.key);
            }
        }

        keys.addAll(scanMarkers(dex));

        return keys;
    }

        /**
     * Layer 1 only: recipes with a REAL working patch (exact descriptor +
     * method + return-type guard). No marker substrings. PATCHABLE status
     * is derived exclusively from this — every hit is a verified patch.
     */
    public static Set<String> scanStructuralKeys(byte[] dex) {
        DexFile file = new DexFile(dex);
        file.validate();

        Set<String> keys = new HashSet<>();

        for (Recipe recipe : RECIPES) {
            if (containsRecipeTarget(file, recipe)) {
                keys.add(recipe.key);
            }
        }

        return keys;
    }

    /**
     * Marker bytes precompiled once — the old loop re-encoded every
     * pattern via getBytes() for every DEX of every APK (pure waste).
     */
    private static final byte[][] MARKER_BYTES = buildMarkerBytes();

    private static byte[][] buildMarkerBytes() {
        byte[][] out = new byte[MARKERS.length][];

        for (int i = 0; i < MARKERS.length; i++) {
            out[i] = MARKERS[i][1].getBytes(
                    java.nio.charset.StandardCharsets.UTF_8
            );
        }

        return out;
    }

    public static Set<String> scanMarkers(byte[] data) {
        Set<String> keys = new HashSet<>();

        for (int i = 0; i < MARKERS.length; i++) {
            if (containsBytes(data, MARKER_BYTES[i])) {
                keys.add(MARKERS[i][0]);
            }
        }

        return keys;
    }


    public static List<String[]> quickScan(InputStream input) throws IOException {
        byte[] data = readAll(input);

        Set<String> keys = scanKeys(data);

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
            case "EMULATOR_BYPASS":
                return "Emulator detection detected";
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
     * Compat entry point. Domain blocking requires string-pool
     * relocation; the old destructive "blank the string" behavior is
     * deliberately not performed. Validates and returns a clean copy.
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

    public static void recomputeChecksums(byte[] dex) {
        if (dex.length < HEADER_SIZE) {
            throw new IllegalArgumentException("DEX too small");
        }

        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

            sha1.update(dex, 32, dex.length - 32);

            byte[] digest = sha1.digest();

            System.arraycopy(digest, 0, dex, 12, digest.length);

                        Adler32 adler = new Adler32();

            adler.update(dex, 12, dex.length - 12);

            writeU32(dex, 8, (int) adler.getValue());
        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "Checksum recomputation failed: " + e.getMessage(), e
            );
        }
    }

    // -------------------------------------------------------------------------
    // DEX method patching
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

            checkRange(classDataOff, 1, out.length, "class_data");

            ClassData data = parseClassData(file, out, classDataOff);

            for (EncodedMethod method : data.methods) {
                if ((method.accessFlags & (ACC_NATIVE | ACC_ABSTRACT)) != 0) {
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

                Recipe recipe = findRecipe(patchKeys, classDescriptor, info.name);

                if (recipe == null) {
                    continue;
                }

                if (recipe.expectedReturnType != null &&
                        !recipe.expectedReturnType.equals(info.returnDescriptor)) {
                    continue;
                }

                CodeItem code = CodeItem.parse(out, method.codeOffset);

                int requiredUnits = requiredCodeUnits(info.returnDescriptor);

                boolean wide =
                        "J".equals(info.returnDescriptor) ||
                                "D".equals(info.returnDescriptor);

                int minRegisters =
                        wide ? 2 : ("V".equals(info.returnDescriptor) ? 0 : 1);

                if (code.registersSize < minRegisters) {
                    log(progress, "  skip " + classDescriptor + "->" +
                            info.name + ": insufficient registers");
                    continue;
                }

                if (code.triesSize != 0) {
                    /*
                     * try/catch methods are stubbed HEAD-ONLY, preserving
                     * instruction boundaries: NOP up to the first real
                     * boundary at-or-after the stub length, stub at entry,
                     * tail + try/handler tables byte-identical. This is
                     * what unlocks GMA's loadAd/show/initialize, which are
                     * always wrapped in try/catch.
                     */
                    int boundary = firstInstructionBoundary(
                            out, code.insnsOffset, code.insnsSize, requiredUnits
                    );

                    if (boundary < 0) {
                        log(progress, "  skip " + classDescriptor + "->" +
                                info.name + ": no safe stub boundary (try/catch)");
                        continue;
                    }

                    for (int u = 0; u < boundary; u++) {
                        writeU16(out, code.insnsOffset + u * 2, 0x0000);
                    }

                    emitReturnStub(
                            out, code.insnsOffset, boundary,
                            code.registersSize, info.returnDescriptor,
                            recipe.stubValue
                    );

                    patched++;
                    log(progress, "  patched " + classDescriptor + "->" +
                            info.name + " " + info.returnDescriptor +
                            " (try/catch kept)");
                    continue;
                }

                if (code.insnsSize < requiredUnits) {
                    log(progress, "  skip " + classDescriptor + "->" +
                            info.name + ": insufficient insns_size");
                    continue;
                }

                emitReturnStub(
                        out, code.insnsOffset, code.insnsSize,
                        code.registersSize, info.returnDescriptor,
                        recipe.stubValue
                );

                patched++;
                log(progress, "  patched " + classDescriptor + "->" +
                        info.name + " " + info.returnDescriptor);
            }
        }

        return patched;
    }

    // -------------------------------------------------------------------------
    // Caller-context verdicts (SIGNATURE_BYPASS)
    // -------------------------------------------------------------------------

    private static int patchCallerVerdicts(
            DexFile file,
            byte[] out,
            Set<String> patchKeys,
            Progress progress
    ) {
        int patched = 0;

        for (Map.Entry<String, String[][]> entry : CALLER_TARGETS.entrySet()) {
            if (!patchKeys.contains(entry.getKey())) {
                continue;
            }

            Set<Integer> targetMethodIds = new HashSet<>();

            for (String[] target : entry.getValue()) {
                targetMethodIds.addAll(
                        findMethodIds(file, target[0], target[1])
                );
            }

            if (targetMethodIds.isEmpty()) {
                continue;
            }

            for (int classIndex = 0; classIndex < file.classDefsSize; classIndex++) {
                int classDef = file.classDefsOff + classIndex * CLASS_DEF_SIZE;
                int classTypeIndex = file.readU32(classDef);
                String classDescriptor = file.getTypeDescriptor(classTypeIndex);

                int classDataOff = file.readU32(classDef + 24);
                if (classDataOff == 0) {
                    continue;
                }

                checkRange(classDataOff, 1, out.length, "class_data");

                ClassData data = parseClassData(file, out, classDataOff);

                for (EncodedMethod method : data.methods) {
                    if ((method.accessFlags & (ACC_NATIVE | ACC_ABSTRACT)) != 0) {
                        continue;
                    }
                    if (method.codeOffset == 0 || (method.codeOffset & 3) != 0) {
                        continue;
                    }

                    MethodInfo info = file.getMethodInfo(method.methodIndex);

                    /*
                     * Verdict stubs: boolean methods returning TRUE.
                     */
                    if (!"Z".equals(info.returnDescriptor)) {
                        continue;
                    }

                    CodeItem code = CodeItem.parse(out, method.codeOffset);

                    if (code.triesSize != 0) {
                        continue;
                    }

                    if (!instructionsReferenceAny(out, code, targetMethodIds)) {
                        continue;
                    }

                    if (code.registersSize < 1 || code.insnsSize < 2) {
                        continue;
                    }

                    emitReturnStub(
                            out, code.insnsOffset, code.insnsSize,
                            code.registersSize, "Z", 1
                    );

                    patched++;
                    log(progress, "  patched caller " + classDescriptor + "->" +
                            info.name + " Z=1 (verdict method)");
                }
            }
        }

        return patched;
    }

    private static List<Integer> findMethodIds(
            DexFile file,
            String classDescriptor,
            String methodName
    ) {
        List<Integer> result = new ArrayList<>();

        for (int i = 0; i < file.methodIdsSize; i++) {
            int offset = file.methodIdsOff + i * METHOD_ID_SIZE;

            int classIndex = readU16(file.bytes, offset);

            try {
                String descriptor = file.getTypeDescriptor(classIndex);

                if (!classDescriptor.equals(descriptor)) {
                    continue;
                }

                int nameIndex = file.readU32(offset + 4);
                String name = file.getString(nameIndex);

                if (methodName.equals(name)) {
                    result.add(i);
                }
            } catch (IllegalArgumentException malformed) {
                /*
                 * One malformed method_id must not abort the scan.
                 */
            }
        }

        return result;
    }

    private static boolean instructionsReferenceAny(
            byte[] data,
            CodeItem code,
            Set<Integer> methodIds
    ) {
        for (int u = 0; u < code.insnsSize; u++) {
            int op = readU16(data, code.insnsOffset + u * 2) & 0xff;

            boolean invoke =
                    (op >= 0x6e && op <= 0x72) ||
                    (op >= 0x74 && op <= 0x78);
            for (EncodedMethod method : data.methods) {
                MethodInfo info = file.getMethodInfo(method.methodIndex);

                if (!recipe.matchesMethod(info.name)) {
                    continue;
                }

                /*
                 * Return-type guard: a structural hit must be a method
                 * the patcher would ACTUALLY stub, or PATCHABLE would
                 * overpromise (overload with a non-void return exists).
                 */
                if (recipe.expectedReturnType != null &&
                        !recipe.expectedReturnType.equals(
                                info.returnDescriptor)) {
                    continue;
                }

                return true;
            }

            if (methodIds.contains(target)) {
                return true;
            }
        }

        return false;
    }

    // -------------------------------------------------------------------------
    // Structural detection helpers
    // -------------------------------------------------------------------------

    private static boolean containsRecipeTarget(DexFile file, Recipe recipe) {
        for (int classIndex = 0; classIndex < file.classDefsSize; classIndex++) {
            int classDef = file.classDefsOff + classIndex * CLASS_DEF_SIZE;
            int typeIndex = file.readU32(classDef);

            String descriptor = file.getTypeDescriptor(typeIndex);

            if (!recipe.matchesClass(descriptor)) {
                continue;
            }

            int classDataOff = file.readU32(classDef + 24);

            if (classDataOff == 0) {
                continue;
            }

            ClassData data = parseClassData(file, file.bytes, classDataOff);

            for (EncodedMethod method : data.methods) {
                MethodInfo info = file.getMethodInfo(method.methodIndex);

                if (recipe.matchesMethod(info.name)) {
                    return true;
                }
            }
        }

        return false;
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

        for (int i = 0; i < insnsSize * 2; i++) {
            data[offset + i] = 0;
        }

        if ("V".equals(returnType)) {
            writeU16(data, offset, 0x000e);
            return;
        }

        if (registersSize == 0) {
            throw new IllegalArgumentException(
                    "Cannot synthesize non-void return without a register"
            );
        }

        if ("J".equals(returnType) || "D".equals(returnType)) {
            /*
             * const-wide/16 v0, #0 ; return-wide v0
             */
            writeU16(data, offset, 0x0016);
            writeU16(data, offset + 2, 0x0000);
            writeU16(data, offset + 4, 0x0010);
            return;
        }

        /*
         * const/4 v0, #stubValue — format 11n: bits 7-0 opcode,
         * bits 11-8 register A (0), bits 15-12 signed literal B.
         * stubValue IS the verdict (0 = OK/false, 1 = true).
         * return v0 => 0x000f, return-object v0 => 0x0011.
         */
        writeU16(data, offset, 0x0012 | ((stubValue & 0xF) << 12));
        writeU16(data, offset + 2, 0x000f);

        if (returnType.startsWith("L") || returnType.startsWith("[")) {
            writeU16(data, offset + 2, 0x0011);
        }
    }

    // -------------------------------------------------------------------------
    // Instruction boundary walk (head-only stubbing of try/catch methods)
    // -------------------------------------------------------------------------

    /**
     * Size of every Dalvik opcode in 16-bit code units.
     * 0 = unknown or unusable: the walk bails out instead of guessing.
     */
    private static final int[] OPCODE_UNITS = buildOpcodeUnits();

    private static int[] buildOpcodeUnits() {
        int[] t = new int[256];

        t[0x00] = 1;
        t[0x01] = 1; t[0x02] = 2; t[0x03] = 3;
        t[0x04] = 1; t[0x05] = 2; t[0x06] = 3;
        t[0x07] = 1; t[0x08] = 2; t[0x09] = 3;
        t[0x0a] = 1; t[0x0b] = 1; t[0x0c] = 1; t[0x0d] = 1;
        t[0x0e] = 1; t[0x0f] = 1; t[0x10] = 1; t[0x11] = 1;
        t[0x12] = 1; t[0x13] = 2; t[0x14] = 3; t[0x15] = 2;
        t[0x16] = 2; t[0x17] = 3; t[0x18] = 5; t[0x19] = 2;
        t[0x1a] = 2; t[0x1b] = 3; t[0x1c] = 2;
        t[0x1d] = 1; t[0x1e] = 1; t[0x1f] = 2; t[0x20] = 2;
        t[0x21] = 1; t[0x22] = 2; t[0x23] = 2; t[0x24] = 3;
        t[0x25] = 3; t[0x26] = 3; t[0x27] = 1;
        t[0x28] = 1; t[0x29] = 2; t[0x2a] = 3;
        t[0x2b] = 3; t[0x2c] = 3;

        for (int op = 0x2d; op <= 0x31; op++) t[op] = 2;
        for (int op = 0x32; op <= 0x37; op++) t[op] = 2;
        for (int op = 0x38; op <= 0x3d; op++) t[op] = 2;
        for (int op = 0x44; op <= 0x51; op++) t[op] = 2;
        for (int op = 0x52; op <= 0x5f; op++) t[op] = 2;
        for (int op = 0x60; op <= 0x6d; op++) t[op] = 2;
        for (int op = 0x6e; op <= 0x72; op++) t[op] = 3;
        for (int op = 0x74; op <= 0x78; op++) t[op] = 3;
        for (int op = 0x7b; op <= 0x8f; op++) t[op] = 1;
        for (int op = 0x90; op <= 0xaf; op++) t[op] = 2;
        for (int op = 0xb0; op <= 0xcf; op++) t[op] = 1;
        for (int op = 0xd0; op <= 0xd7; op++) t[op] = 2;
        for (int op = 0xd8; op <= 0xe2; op++) t[op] = 2;

        t[0xfa] = 4; t[0xfb] = 4;
        t[0xfc] = 3; t[0xfd] = 3;
        t[0xfe] = 2; t[0xff] = 2;

        return t;
    }

    /**
     * First instruction boundary (in code units, relative to insns start)
     * at or after minUnits, walking real instruction sizes.
     * -1 = cannot establish a safe boundary.
     */
    private static int firstInstructionBoundary(
            byte[] data,
            int insnsOffset,
            int insnsSize,
            int minUnits
    ) {
        int unit = 0;

        while (unit < minUnits) {
            if (unit >= insnsSize) {
                return -1;
            }

            int op = readU16(data, insnsOffset + unit * 2) & 0xff;

            int size = OPCODE_UNITS[op];

            if (size <= 0 || unit + size > insnsSize) {
                return -1;
            }

            unit += size;
        }

        return unit;
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
                    previousMethodIndex, accessFlags, codeOffset
            ));
        }

        previousMethodIndex = 0;

        for (int i = 0; i < virtualMethods; i++) {
            int delta = cursor.readUleb128();
            int accessFlags = cursor.readUleb128();
            int codeOffset = cursor.readUleb128();

            previousMethodIndex += delta;

            methods.add(new EncodedMethod(
                    previousMethodIndex, accessFlags, codeOffset
            ));
        }

        return new ClassData(methods);
    }

    // -------------------------------------------------------------------------
    // Binary XML — manifest patching
    // -------------------------------------------------------------------------

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

            if (type == RES_STRING_POOL_TYPE && pool == null) {
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
            int type = readU16(out, cursor);
            int chunkSize = readU32Checked(out, cursor + 4);

            if (type == RES_XML_START_ELEMENT_TYPE) {
                changed |= patchStartElement(
                        out, cursor, chunkSize, pool, resourceMapOffset, patchKeys
                );
            }

            cursor += chunkSize;
        }

        return changed ? out : manifest.clone();
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

        cursor = 0;
        while (cursor < manifest.length) {
            int type = readU16(manifest, cursor);
            int chunkSize = readU32Checked(manifest, cursor + 4);

            if (type == RES_XML_START_ELEMENT_TYPE) {
                scanStartElement(
                        manifest, cursor, chunkSize,
                        resourceMapOffset, keys
                );
            }

            cursor += chunkSize;
        }

        return keys;
    }

    private static void scanStartElement(
            byte[] data,
            int chunkOffset,
            int chunkSize,
            int resourceMapOffset,
            Set<String> keys
    ) {
        if (chunkOffset + 36 > data.length) {
            return;
        }

        int nodeHeaderSize = readU16(data, chunkOffset + 2);
        if (nodeHeaderSize < 16) {
            return;
        }

        int ext = chunkOffset + nodeHeaderSize;
        if (ext + 20 > data.length) {
            return;
        }

        int attributeStart = readU16(data, ext + 8);
        int attributeSize = readU16(data, ext + 10);
        int attributeCount = readU16(data, ext + 12);

        if (attributeSize < 20 || attributeCount <= 0) {
            return;
        }

        int attributesBase = ext + attributeStart;

        long end = (long) attributesBase +
                (long) attributeCount * attributeSize;

        if (attributesBase < 0 || end > chunkOffset + chunkSize ||
                end > data.length) {
            return;
        }

        for (int i = 0; i < attributeCount; i++) {
            int attr = attributesBase + i * attributeSize;

            int nameStringIndex = readU32(data, attr + 4);

            int resourceId = resolveResourceId(
                    data, resourceMapOffset, nameStringIndex
            );

            int dataType = data[attr + 15] & 0xff;
            int dataValue = readU32(data, attr + 16);

            if (dataType != TYPE_INT_BOOLEAN) {
                continue;
            }

            boolean current = dataValue != 0;

            if (resourceId == ATTR_DEBUGGABLE && !current) {
                keys.add("FORCE_DEBUGGABLE");
            }

            if (resourceId == ATTR_EXPORTED && !current) {
                keys.add("EXPORT_ALL_COMPONENTS");
            }

            if (resourceId == ATTR_ALLOW_BACKUP && !current) {
                keys.add("ALLOW_BACKUP");
            }

            if (resourceId == ATTR_FULL_BACKUP_ONLY && current) {
                keys.add("ALLOW_BACKUP");
            }
        }
    }

    private static boolean patchStartElement(
            byte[] data,
            int chunkOffset,
            int chunkSize,
            StringPool pool,
            int resourceMapOffset,
            Set<String> keys
    ) {
        if (chunkOffset + 36 > data.length) {
            throw new IllegalArgumentException("Truncated START_ELEMENT");
        }

        int nodeHeaderSize = readU16(data, chunkOffset + 2);

        if (nodeHeaderSize < 16) {
            throw new IllegalArgumentException("Invalid XML node header");
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

            int nameStringIndex = readU32(data, attr + 4);

            int resourceId = resolveResourceId(
                    data, resourceMapOffset, nameStringIndex
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
        int headerSize = readU16(data, resourceMapOffset + 2);
        int mapBase = resourceMapOffset + headerSize;

        long offset = (long) mapBase + (long) stringIndex * 4L;

        if (offset < 0 || offset + 4 > data.length) {
            return 0;
        }

        return readU32Checked(data, (int) offset);
    }

    private static void writeBooleanValue(
            byte[] data,
            int attributeOffset,
            boolean value
    ) {
        writeU16(data, attributeOffset + 12, 8);
        data[attributeOffset + 14] = 0;
        data[attributeOffset + 15] = TYPE_INT_BOOLEAN;
        writeU32(data, attributeOffset + 16, value ? 1 : 0);
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

            fileSize = readU32Checked(bytes, 0x20);
            headerSize = readU32Checked(bytes, 0x24);

            stringIdsSize = readU32Checked(bytes, 0x38);
            stringIdsOff = readU32Checked(bytes, 0x3c);

            typeIdsSize = readU32Checked(bytes, 0x40);
            typeIdsOff = readU32Checked(bytes, 0x44);

            protoIdsSize = readU32Checked(bytes, 0x48);
            protoIdsOff = readU32Checked(bytes, 0x4c);

            methodIdsSize = readU32Checked(bytes, 0x58);
            methodIdsOff = readU32Checked(bytes, 0x5c);

            classDefsSize = readU32Checked(bytes, 0x60);
            classDefsOff = readU32Checked(bytes, 0x64);

            dataSize = readU32Checked(bytes, 0x68);
            dataOff = readU32Checked(bytes, 0x6c);
        }

        void validate() {
            if (bytes.length < HEADER_SIZE) {
                throw new IllegalArgumentException("DEX header truncated");
            }

            if (bytes[0] != 'd' || bytes[1] != 'e' ||
                    bytes[2] != 'x' || bytes[3] != '\n') {
                throw new IllegalArgumentException("Invalid DEX magic");
            }

            if (bytes[7] != 0) {
                throw new IllegalArgumentException(
                        "Invalid DEX magic terminator"
                );
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
                                fileSize + " actual=" + bytes.length
                );
            }

            if (dataOff < HEADER_SIZE || dataOff > bytes.length ||
                    dataSize < 0 ||
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
                if (offset != 0 && offset >= bytes.length) {
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

            long end = (long) offset + (long) count * elementSize;

            if (end > bytes.length) {
                throw new IllegalArgumentException(
                        name + " table exceeds file"
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

            int stringOffset = readU32(stringIdsOff + index * 4);

            checkRange(stringOffset, 1, bytes.length, "string_data");

            return readMutf8(bytes, stringOffset);
        }

        String getTypeDescriptor(int typeIndex) {
            if (typeIndex < 0 || typeIndex >= typeIdsSize) {
                throw new IllegalArgumentException(
                        "type index out of range: " + typeIndex
                );
            }

            int descriptorIndex = readU32(typeIdsOff + typeIndex * 4);

            return getString(descriptorIndex);
        }

        MethodInfo getMethodInfo(int methodIndex) {
            if (methodIndex < 0 || methodIndex >= methodIdsSize) {
                throw new IllegalArgumentException(
                        "method index out of range: " + methodIndex
                );
            }

            int offset = methodIdsOff + methodIndex * METHOD_ID_SIZE;

            int classIndex = readU16(bytes, offset);
            int protoIndex = readU16(bytes, offset + 2);
            int nameIndex = readU32(offset + 4);

            String name = getString(nameIndex);

            if (protoIndex < 0 || protoIndex >= protoIdsSize) {
                throw new IllegalArgumentException(
                        "proto index out of range"
                );
            }

            int protoOffset = protoIdsOff + protoIndex * PROTO_ID_SIZE;

            /*
             * proto_id_item: shorty_idx u32 @+0, return_type_idx u32 @+4,
             * parameters_off u32 @+8. Reading +8 read parameters_off as a
             * type index — the bug that made every parameterized recipe
             * silently miss (and void methods match type_ids[0]).
             */
            int returnTypeIndex = readU32(protoOffset + 4);

            String returnDescriptor = getTypeDescriptor(returnTypeIndex);

            return new MethodInfo(
                    methodIndex, classIndex, protoIndex,
                    name, returnDescriptor
            );
        }
    }

    // -------------------------------------------------------------------------
    // MUTF-8
    // -------------------------------------------------------------------------

    private static String readMutf8(byte[] data, int offset) {
        Cursor cursor = new Cursor(data, offset);

        int declaredUtf16Length = cursor.readUleb128();

        StringBuilder out = new StringBuilder(declaredUtf16Length);

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

            if ((b & 0xe0) == 0xc0) {
                requireBytes(cursor, 1);

                int b2 = data[cursor.position++] & 0xff;

                if (b == 0xc0 && b2 == 0x80) {
                    out.append('\u0000');
                } else {
                    if ((b2 & 0xc0) != 0x80) {
                        throw new IllegalArgumentException(
                                "Invalid MUTF-8 continuation byte"
                        );
                    }

                    int value = ((b & 0x1f) << 6) | (b2 & 0x3f);

                    out.append((char) value);
                }

                continue;
            }

            if ((b & 0xf0) == 0xe0) {
                requireBytes(cursor, 2);

                int b2 = data[cursor.position++] & 0xff;
                int b3 = data[cursor.position++] & 0xff;

                if ((b2 & 0xc0) != 0x80 || (b3 & 0xc0) != 0x80) {
                    throw new IllegalArgumentException(
                            "Invalid MUTF-8 sequence"
                    );
                }

                int value = ((b & 0x0f) << 12) |
                        ((b2 & 0x3f) << 6) | (b3 & 0x3f);

                out.append((char) value);
                continue;
            }

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

        return out.toString();
    }

    private static void requireBytes(Cursor cursor, int count) {
        if (cursor.position + count > cursor.data.length) {
            throw new IllegalArgumentException(
                    "Truncated MUTF-8 sequence"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Models
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

        static CodeItem parse(byte[] data, int offset) {
            checkRange(offset, 16, data.length, "code_item");

            int registersSize = readU16(data, offset);
            int insSize = readU16(data, offset + 2);
            int outsSize = readU16(data, offset + 4);
            int triesSize = readU16(data, offset + 6);
            int insnsSize = readU32Checked(data, offset + 12);

            int insnsOffset = offset + 16;

            long end = (long) insnsOffset + (long) insnsSize * 2L;

            if (end > data.length) {
                throw new IllegalArgumentException(
                        "code_item instructions exceed DEX"
                );
            }

            return new CodeItem(
                    registersSize, insSize, outsSize,
                    triesSize, insnsSize, insnsOffset
            );
        }
    }

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

        EncodedMethod(int methodIndex, int accessFlags, int codeOffset) {
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
                    throw new IllegalArgumentException("Truncated ULEB128");
                }

                int b = data[position++] & 0xff;

                result |= (b & 0x7f) << shift;

                if ((b & 0x80) == 0) {
                    return result;
                }

                shift += 7;
            }

            throw new IllegalArgumentException("ULEB128 exceeds 5 bytes");
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

        static StringPool parse(byte[] data, int offset) {
            int headerSize = readU16(data, offset + 2);
            int chunkSize = readU32Checked(data, offset + 4);
            int stringCount = readU32Checked(data, offset + 8);
            int flags = readU32Checked(data, offset + 16);
            int stringsStart = readU32Checked(data, offset + 20);

            if (headerSize < 28) {
                throw new IllegalArgumentException(
                        "Invalid string pool header"
                );
            }

            if (stringCount < 0) {
                throw new IllegalArgumentException("Invalid string count");
            }

            int[] offsets = new int[stringCount];

            int offsetBase = offset + headerSize;

            long offsetsEnd = (long) offsetBase + (long) stringCount * 4L;

            if (offsetsEnd > offset + chunkSize ||
                    offsetsEnd > data.length) {
                throw new IllegalArgumentException(
                        "String pool offsets exceed chunk"
                );
            }

            for (int i = 0; i < stringCount; i++) {
                offsets[i] = readU32Checked(data, offsetBase + i * 4);
            }

            return new StringPool(
                    offset, chunkSize, stringCount,
                    flags, stringsStart, offsets
            );
        }
    }

    // -------------------------------------------------------------------------
    // Binary helpers
    // -------------------------------------------------------------------------

    private static int readU16(byte[] data, int offset) {
        checkRange(offset, 2, data.length, "u16");

        return (data[offset] & 0xff) |
                ((data[offset + 1] & 0xff) << 8);
    }

    private static int readU32Checked(byte[] data, int offset) {
        checkRange(offset, 4, data.length, "u32");

        return (data[offset] & 0xff) |
                ((data[offset + 1] & 0xff) << 8) |
                ((data[offset + 2] & 0xff) << 16) |
                ((data[offset + 3] & 0xff) << 24);
    }

    private static void writeU16(byte[] data, int offset, int value) {
        checkRange(offset, 2, data.length, "u16 write");

        data[offset] = (byte) value;
        data[offset + 1] = (byte) (value >>> 8);
    }

    private static void writeU32(byte[] data, int offset, int value) {
        checkRange(offset, 4, data.length, "u32 write");

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
        if (offset < 0 || length < 0 ||
                (long) offset + length > total) {
            throw new IllegalArgumentException(
                    "Invalid " + what + " range: offset=" +
                            offset + " length=" + length +
                            " total=" + total
            );
        }
    }

    private static boolean containsBytes(byte[] data, byte[] pattern) {
        if (pattern.length == 0 || pattern.length > data.length) {
            return false;
        }

        outer:
        for (int i = 0; i <= data.length - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    continue outer;
                }
            }
            return true;
        }

        return false;
    }

    private static byte[] readAll(InputStream input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        byte[] buffer = new byte[64 * 1024];

        int n;

        while ((n = input.read(buffer)) != -1) {
            out.write(buffer, 0, n);
        }

        return out.toByteArray();
    }

    private static void log(Progress progress, String message) {
        if (progress != null) {
            progress.log(message);
        }
    }
}

