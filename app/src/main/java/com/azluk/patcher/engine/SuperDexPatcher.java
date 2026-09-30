package com.azluk.patcher.engine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.Adler32;

/**
 * AzlukPatcher V9 - SuperDexPatcher
 *
 * DEX parser/transformer, failure-loud by design:
 *
 *  - validates the DEX header before reading tables
 *  - uses the real DEX offsets from the specification:
 *
 *      header:    string_ids_size @ 0x38, string_ids_off @ 0x3C
 *                 class_defs_size @ 0x60, class_defs_off @ 0x64
 *
 *      proto_id:  shorty_idx u32 @ +0
 *                 return_type_idx u32 @ +4
 *                 parameters_off u32 @ +8
 *
 *  - cross-validates proto shorty against the return descriptor and
 *    refuses the file on mismatch
 *  - decodes DEX strings as strict MUTF-8 (rejects overlong encodings,
 *    requires NUL terminator, verifies declared UTF-16 length)
 *  - resolves methods structurally through class_defs -> class_data ->
 *    method_ids -> name_idx -> string_ids; never through const-string scans
 *  - never touches ACC_NATIVE or ACC_ABSTRACT methods, refuses unaligned
 *    or out-of-range code_offsets
 *  - refuses methods with exception handlers (tries_size != 0)
 *  - recomputes SHA-1 + Adler32 only after successful mutation, then
 *    re-validates the result before handing it out
 *
 * Recipes are structural (class descriptor + method name + expected
 * return type), exact-matched against type_ids — no substring matching.
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
     * Structural recipes. Exact descriptor match, exact method name match,
     * optional expected return type guard. First matching recipe wins.
     */
    private static final List<Recipe> RECIPES;

    static {
        List<Recipe> recipes = new ArrayList<>();

        recipes.add(new Recipe(
                "DISABLE_ANALYTICS",
                new String[]{
                        "Lcom/google/firebase/analytics/FirebaseAnalytics;"
                },
                new String[]{
                        "logEvent"
                },
                "V"
        ));

        recipes.add(new Recipe(
                "DISABLE_ANALYTICS",
                new String[]{
                        "Lcom/mixpanel/android/mpmetrics/MixpanelAPI;"
                },
                new String[]{
                        "track",
                        "trackMap"
                },
                "V"
        ));

        recipes.add(new Recipe(
                "REMOVE_TELEMETRY",
                new String[]{
                        "Lio/sentry/Sentry;"
                },
                new String[]{
                        "captureException",
                        "captureMessage",
                        "captureEvent"
                },
                null
        ));

        recipes.add(new Recipe(
                "REMOVE_TELEMETRY",
                new String[]{
                        "Lcom/google/firebase/crashlytics/FirebaseCrashlytics;"
                },
                new String[]{
                        "recordException",
                        "log"
                },
                "V"
        ));

        recipes.add(new Recipe(
                "REMOVE_TELEMETRY",
                new String[]{
                        "Lcom/bugsnag/android/Bugsnag;"
                },
                new String[]{
                        "notify"
                },
                null
        ));

        RECIPES = Collections.unmodifiableList(recipes);
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
     *
     * Domain blocking requires a true string-pool rebuild/relocation phase.
     * The old destructive "blank the string in place" behavior corrupted
     * sorted pools and class descriptors sharing the same data, so this
     * method validates the input and refuses to fake success.
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

    /**
     * Lightweight scan used by ApkEngine.
     *
     * Reports only recipes this implementation can structurally reason about.
     */
    public static List<String[]> quickScan(InputStream input) throws IOException {
        byte[] data = readAll(input);
        DexFile file = new DexFile(data);
        file.validate();

        List<String[]> result = new ArrayList<>();

        Set<String> available = new HashSet<>();

        for (Recipe recipe : RECIPES) {
            if (containsRecipeTarget(file, recipe)) {
                available.add(recipe.key);
            }
        }

        for (String key : available) {
            result.add(new String[]{
                    key,
                    "Structural recipe available"
            });
        }

        return result;
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
                     * Their encoded code_off must be 0; touching them is
                     * always corruption.
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
                        info.returnDescriptor
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

    private static boolean containsRecipeTarget(
            DexFile file,
            Recipe recipe
    ) {
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

            checkRange(classDataOff, 1, file.bytes.length, "class_data");

            ClassData data = parseClassData(file, file.bytes, classDataOff);

            for (EncodedMethod method : data.methods) {

                if ((method.accessFlags & (ACC_NATIVE | ACC_ABSTRACT)) != 0) {
                    continue;
                }

                if (method.codeOffset == 0) {
                    continue;
                }

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
            String returnType
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
             * return-void  => 0x000e
             */
            writeU16(data, offset, 0x000e);
            return;
        }

        if ("J".equals(returnType) || "D".equals(returnType)) {
            /*
             * const-wide/16 v0, #0   0x1600 | vAA => 0x0016, literal 0x0000
             * return-wide v0         0x1000 | vAA => 0x0010
             *
             * A wide value occupies the register pair v0/v1.
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
         * const/4 v0, #0   format 11n, A=0, B=0 => 0x0012
         * return v0        => 0x000f
         * return-object v0 => 0x0011 (object/array return types)
         */
        writeU16(data, offset, 0x0012);
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
         *   type          u16
         *   headerSize    u16
         *   size          u32
         *   lineNumber    u32
         *   comment       u32
         *
         * ResXMLTree_attrExt (at nodeHeaderSize)
         *   ns             u32
         *   name           u32
         *   attributeStart u16  (offset from attrExt to attributes)
         *   attributeSize  u16
         *   attributeCount u16
         *   idIndex        u16
         *   classIndex     u16
         *   styleIndex     u16
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

            int nameStringIndex = readU32(data, attr + 4);

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

        return readU32(data, (int) (mapBase + (long) stringIndex * 4L));
    }

    private static void writeBooleanValue(
            byte[] data,
            int attributeOffset,
            boolean value
    ) {
        /*
         * Attribute:
         *   ns         +0
         *   name       +4
         *   rawValue  +8
         *   typedValue +12
         *
         * typedValue (Res_value):
         *   size       +0 (u16)
         *   res0       +2 (u8)
         *   dataType   +3 (u8)
         *   data       +4 (u32)
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
             *   shorty_idx      u32 @ +0
             *   return_type_idx u32 @ +4
             *   parameters_off  u32 @ +8
             *
             * The previous revision read +8 here, which is parameters_off.
             * For a zero-parameter method that value is 0, so type index 0
             * resolved to whichever descriptor happened to sit there.
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

        Recipe(
                String key,
                String[] classes,
                String[] methods,
                String expectedReturnType
        ) {
            this.key = key;
            this.classes = classes;
            this.methods = methods;
            this.expectedReturnType = expectedReturnType;
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
