package me.naptila.deobfuscator;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.strings.StringFogXorDecoder;
import me.naptila.deobfuscator.strings.StringDecoder;
import me.naptila.deobfuscator.transformers.strings.StringDecryptTransformer;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.MethodImplementationBuilder;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.StringReference;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.jf.dexlib2.immutable.value.ImmutableIntEncodedValue;
import org.junit.Test;
import static org.junit.Assert.*;

public class StringFogXorTest {
    static final String SIGNATURE = "Lsample/Fog;->decrypt(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;";
    @Test public void decodesBytesAndUtf8WithCyclicKey() {
        var decoder = new StringFogXorDecoder(SIGNATURE);
        for (String plain : List.of("", "ASCII", "中文\u0000😀")) {
            byte[] bytes = plain.getBytes(StandardCharsets.UTF_8), key = {(byte)0x81, 7, (byte)0xff};
            for (int i = 0; i < bytes.length; i++) bytes[i] ^= key[i % key.length];
            String text = Base64.getEncoder().withoutPadding().encodeToString(bytes);
            assertEquals(Optional.of(plain), decoder.decode(SIGNATURE, List.of("\n" + text + "\r\n", Base64.getEncoder().encodeToString(key))));
        }
    }
    @Test public void rejectsUnknownArgumentsInvalidBase64AndEmptyKeyForNonemptyText() {
        var decoder = new StringFogXorDecoder(SIGNATURE);
        for (List<Object> args : List.of(Arrays.<Object>asList(null, "QQ=="), List.<Object>of("!", "QQ=="), List.<Object>of("QQ==", "")))
            assertTrue(decoder.decode(SIGNATURE, args).isEmpty());
        assertTrue(decoder.decode(SIGNATURE + "wrong", List.of("", "")).isEmpty());
        assertEquals(Optional.of(""), decoder.decode(SIGNATURE, List.of("", "")));
    }
    @Test public void decryptsThroughStringCastsAndRetainsCallsAndHandlers() {
        var input = castFixture("Ljava/lang/String;", false);
        var pass = new StringDecryptTransformer(List.of(new StringFogXorDecoder(SIGNATURE)));
        var result = new DexEngine(List.of(pass), 5).transform(Fixtures.dex(input));
        assertEquals(0, result.failedMethods());
        assertEquals(1, result.changedMethods());
        var output = Fixtures.first(result.dex());
        var graph = new CodeGraph(output.getImplementation());
        assertEquals(input.getImplementation().getTryBlocks().size(), output.getImplementation().getTryBlocks().size());
        int casts = 0, calls = 0; boolean plaintext = false;
        for (int i = 0; i < graph.size(); i++) {
            if (graph.at(i).getOpcode() == Opcode.CHECK_CAST) {
                casts++; assertFalse(graph.protection(i).isEmpty());
            }
            if (graph.at(i).getOpcode() == Opcode.INVOKE_STATIC) calls++;
            if (graph.at(i) instanceof ReferenceInstruction r && r.getReference() instanceof StringReference s)
                plaintext |= s.getString().equals("hello");
        }
        assertEquals(1, casts); assertEquals(1, calls); assertTrue(plaintext);
        assertEquals(0, new DexEngine(List.of(pass), 5).transform(result.dex()).changedMethods());
    }
    @Test public void unknownOrIncompatibleCastsKeepEncryptedResults() {
        for (Method input : List.of(castFixture("Ljava/lang/String;", true), castFixture("Ljava/lang/StringBuilder;", false))) {
            var result = new DexEngine(List.of(new StringDecryptTransformer(List.of(new StringFogXorDecoder(SIGNATURE)))), 5)
                    .transform(Fixtures.dex(input));
            assertEquals(0, result.failedMethods());
            assertEquals(0, result.changedMethods());
        }
    }
    @Test public void catchPathsPreserveUnaffectedArgumentsAndSelectReassignedKeys() {
        for (boolean overwriteKey : new boolean[]{false, true}) {
            var pass = new StringDecryptTransformer(List.of(new StringFogXorDecoder(SIGNATURE)));
            var result = new DexEngine(List.of(pass), 5).transform(Fixtures.dex(handlerFixture(overwriteKey)));
            assertEquals(0, result.failedMethods());
            assertEquals(1, result.changedMethods());
            int calls = 0;
            for (var i : Fixtures.first(result.dex()).getImplementation().getInstructions())
                if (i.getOpcode() == Opcode.INVOKE_STATIC) calls++;
            assertEquals(2, calls);
            if (overwriteKey) {
                Set<String> strings = new HashSet<>();
                for (var i : Fixtures.first(result.dex()).getImplementation().getInstructions())
                    if (i instanceof ReferenceInstruction r && r.getReference() instanceof StringReference s) strings.add(s.getString());
                assertTrue(strings.containsAll(List.of("hello", "idmmn")));
            }
        }
    }
    @Test public void decryptsThroughGuardedObjectProxiesAndPreservesCalls() throws Exception {
        for (String mode : List.of("known", "alias", "range", "protected", "chain", "sample-literal")) {
            var result = decryptProxies(proxyFixture(mode));
            assertEquals(mode, 0, result.failedMethods());
            Method caller = new DexContext(result.dex()).methods().get("Lsample/Test;->proxyCall()Ljava/lang/String;");
            CodeGraph graph = new CodeGraph(caller.getImplementation());
            int calls = 0; boolean plain = false;
            for (int i = 0; i < graph.size(); i++) {
                var insn = graph.at(i);
                if (insn instanceof ReferenceInstruction r && r.getReference() instanceof StringReference s
                        && s.getString().equals(mode.equals("sample-literal") ? "GameDetector" : "hello")) plain = true;
                if (insn.getOpcode() == Opcode.INVOKE_STATIC || insn.getOpcode() == Opcode.INVOKE_STATIC_RANGE) calls++;
            }
            assertTrue(mode, plain);
            assertEquals(mode, mode.equals("chain") ? 2 : 1, calls);
            assertEquals(mode, 0, decryptProxies(result.dex()).changedMethods());
        }
    }
    @Test public void unprovenGuardsArgumentsCastsAndCyclesKeepProxyResults() throws Exception {
        for (String mode : List.of("unknown", "mutated", "cycle", "wrong-cast", "unknown-arg", "guard-cycle")) {
            var result = decryptProxies(proxyFixture(mode));
            assertEquals(mode, 0, result.failedMethods());
            assertEquals(mode, 0, result.changedMethods());
        }
    }
    @Test public void configuredDecodersStillAllowArgumentSpecificFallbacks() {
        StringDecoder unavailable = new StringDecoder() {
            public String id() { return "test.unavailable"; }
            public boolean supports(String signature) { return SIGNATURE.equals(signature); }
            public Optional<String> decode(String signature, List<Object> arguments) { return Optional.empty(); }
        };
        var pass = new StringDecryptTransformer(List.of(unavailable, new StringFogXorDecoder(SIGNATURE)));
        var result = new DexEngine(List.of(pass), 5).transform(Fixtures.dex(castFixture("Ljava/lang/String;", false)));
        assertEquals(0, result.failedMethods()); assertEquals(1, result.changedMethods());
    }
    private static final ImmutableMethodReference FOG = new ImmutableMethodReference("Lsample/Fog;", "decrypt",
            List.of("Ljava/lang/String;", "Ljava/lang/String;"), "Ljava/lang/String;");
    private static final String CLEANUP_PROBE = "LStringFogCleanupProbe;";
    private static void cleanupCall(MethodImplementationBuilder b, int first, String cipher, boolean result) {
        Fixtures.string(b, first, cipher); Fixtures.string(b, first + 1, "AA==");
        b.addInstruction(first > 15 ? new BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, first, 2, FOG)
                : new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, first, first + 1, 0, 0, 0, FOG));
        if (result) b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
    }
    private static void cleanupEffect(MethodImplementationBuilder b, String name) {
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference(CLEANUP_PROBE, name, List.of(), "V")));
    }
    private static DexFile cleanupFixture(String mode) {
        // Actual Base64 / cyclic byte XOR / UTF-8 implementation for ART checks.
        var b = new MethodImplementationBuilder(8);
        if (mode.equals("unknown-first")) b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 6, b.getLabel("null")));
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, new ImmutableFieldReference("Lsample/FogDependency;", "loaded", "I")));
        Fixtures.integer(b, 0, 0);
        var base64 = new ImmutableMethodReference("Landroid/util/Base64;", "decode", List.of("Ljava/lang/String;", "I"), "[B");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 6, 0, 0, 0, 0, base64));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 7, 0, 0, 0, 0, base64));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 2));
        b.addInstruction(new BuilderInstruction12x(Opcode.ARRAY_LENGTH, 3, 1));
        b.addInstruction(new BuilderInstruction12x(Opcode.ARRAY_LENGTH, 4, 2));
        b.addLabel("loop"); b.addInstruction(new BuilderInstruction22t(Opcode.IF_GE, 0, 3, b.getLabel("done")));
        b.addInstruction(new BuilderInstruction23x(Opcode.REM_INT, 5, 0, 4));
        b.addInstruction(new BuilderInstruction23x(Opcode.AGET_BYTE, 5, 2, 5));
        b.addInstruction(new BuilderInstruction23x(Opcode.AGET_BYTE, 6, 1, 0));
        b.addInstruction(new BuilderInstruction12x(Opcode.XOR_INT_2ADDR, 5, 6));
        b.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_BYTE, 5, 5));
        b.addInstruction(new BuilderInstruction23x(Opcode.APUT_BYTE, 5, 1, 0));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, 1)); Fixtures.go(b, "loop");
        b.addLabel("done"); b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 0, new ImmutableTypeReference("Ljava/lang/String;")));
        Fixtures.string(b, 2, "UTF-8");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 3, 0, 1, 2, 0, 0,
                new ImmutableMethodReference("Ljava/lang/String;", "<init>", List.of("[B", "Ljava/lang/String;"), "V")));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        if (mode.equals("unknown-first")) {
            b.addLabel("null"); Fixtures.integer(b, 0, 0); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        }
        Method decrypt = proxyMethod("Lsample/Fog;", "decrypt", List.of("Ljava/lang/String;", "Ljava/lang/String;"), "Ljava/lang/String;", b.getMethodImplementation());
        if (mode.equals("synchronized")) decrypt = new ImmutableMethod(decrypt.getDefiningClass(), decrypt.getName(), decrypt.getParameters(),
                decrypt.getReturnType(), decrypt.getAccessFlags() | AccessFlags.DECLARED_SYNCHRONIZED.getValue(), Set.of(), Set.of(), decrypt.getImplementation());
        var fogLoaded = new ImmutableField("Lsample/Fog;", "loaded", "I", AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(), new ImmutableIntEncodedValue(1), Set.of(), Set.of());
        b = new MethodImplementationBuilder(0); cleanupEffect(b, "initialize"); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        var classes = new ArrayList<ClassDef>();
        if (!mode.equals("unresolved")) classes.add(new ImmutableClassDef("Lsample/Fog;", AccessFlags.PUBLIC.getValue(), "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(fogLoaded),
                List.of(decrypt, proxyMethod("Lsample/Fog;", "<clinit>", List.of(), "V", b.getMethodImplementation()))));
        b = new MethodImplementationBuilder(0); cleanupEffect(b, "initializeDependency"); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        var dependencyField = new ImmutableField("Lsample/FogDependency;", "loaded", "I", AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(), new ImmutableIntEncodedValue(1), Set.of(), Set.of());
        classes.add(new ImmutableClassDef("Lsample/FogDependency;", AccessFlags.PUBLIC.getValue(), "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(dependencyField),
                List.of(proxyMethod("Lsample/FogDependency;", "<clinit>", List.of(), "V", b.getMethodImplementation()))));
        int first = mode.equals("range") ? 16 : 0;
        b = new MethodImplementationBuilder(first == 16 ? 20 : 4);
        if (mode.equals("field-initialized")) b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 2, fogLoaded));
        if (mode.startsWith("branch")) b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 3, b.getLabel("other")));
        b.addLabel("start");
        if (mode.equals("unknown-first")) {
            Fixtures.string(b, 1, "AA==");
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                    new ImmutableMethodReference(CLEANUP_PROBE, "unknownCipher", List.of(), "Ljava/lang/String;")));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 0, 1, 0, 0, 0, FOG));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        } else cleanupCall(b, first, "aGVsbG8=", true);
        b.addLabel("end");
        if (mode.startsWith("branch") || mode.equals("exception")) {
            Fixtures.go(b, "join"); b.addLabel("other");
            if (mode.equals("exception")) b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 2));
            if (!mode.equals("branch-missing")) cleanupCall(b, first, "Ynll", true);
            b.addLabel("join");
        }
        cleanupEffect(b, "touch");
        if (mode.equals("unknown")) {
            Fixtures.string(b, first, "YXJtNjQ=");
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                    new ImmutableMethodReference(CLEANUP_PROBE, "unknownKey", List.of(), "Ljava/lang/String;")));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, first + 1));
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, first, first + 1, 0, 0, 0, FOG));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        } else cleanupCall(b, first, mode.equals("invalid") ? "A" : "YXJtNjQ=", !mode.equals("dead"));
        if (mode.equals("dead")) Fixtures.string(b, 0, "arm64");
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        if (mode.equals("protected")) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
            Fixtures.string(b, 0, "caught"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
            b.addCatch("Ljava/lang/Throwable;", b.getLabel("start"), b.getLabel("handler"), b.getLabel("handler"));
        } else if (mode.equals("exception")) b.addCatch("Ljava/lang/Throwable;", b.getLabel("start"), b.getLabel("end"), b.getLabel("other"));
        classes.add(proxyClass("Lsample/Test;", List.of(proxyMethod("Lsample/Test;", "cleanup", List.of("I"), "Ljava/lang/String;", b.getMethodImplementation()))));
        return new ImmutableDexFile(Opcodes.forApi(28), classes);
    }
    private static DexEngine.Result cleanupStrings(DexFile input, boolean remove) {
        return new DexEngine(List.of(new StringDecryptTransformer(List.of(new StringFogXorDecoder(SIGNATURE)), remove ? Set.of(SIGNATURE) : Set.of())), 10).transform(input);
    }
    private static long cleanupCalls(DexFile dex) {
        Method caller = new DexContext(dex).methods().get("Lsample/Test;->cleanup(I)Ljava/lang/String;");
        long calls = 0;
        for (var i : caller.getImplementation().getInstructions()) if (i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m && Signatures.of(m).equals(SIGNATURE)) calls++;
        return calls;
    }
    private static DexFile cleanupProxyFixture(String mode) {
        DexFile input = cleanupFixture(mode.equals("unknown-first") ? "unknown-first" : "straight");
        var proxy = new ImmutableMethodReference("Lsample/Forwarder;", "decode", List.of("Ljava/lang/Object;", "Ljava/lang/Object;"), "Ljava/lang/String;");
        var inner = new ImmutableMethodReference("Lsample/Nested;", "decode", proxy.getParameterTypes(), proxy.getReturnType());
        var b = new MethodImplementationBuilder(3);
        if (mode.equals("effects")) cleanupEffect(b, "touch");
        if (mode.equals("throws")) {
            Fixtures.integer(b, 0, 0); b.addInstruction(new BuilderInstruction23x(Opcode.DIV_INT, 0, 0, 0));
        }
        b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 1, new ImmutableTypeReference("Ljava/lang/String;")));
        b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 2, new ImmutableTypeReference("Ljava/lang/String;")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 1, 2, 0, 0, 0, mode.equals("nested") ? inner : FOG));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        var methods = new ArrayList<Method>();
        methods.add(proxyMethod(proxy.getDefiningClass(), proxy.getName(), proxy.getParameterTypes(), proxy.getReturnType(), b.getMethodImplementation()));
        if (mode.equals("initializer")) {
            b = new MethodImplementationBuilder(0); cleanupEffect(b, "initialize"); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            methods.add(proxyMethod(proxy.getDefiningClass(), "<clinit>", List.of(), "V", b.getMethodImplementation()));
        }
        var classes = new ArrayList<ClassDef>();
        for (ClassDef cls : input.getClasses()) {
            var rewritten = new ArrayList<Method>();
            for (Method method : cls.getMethods()) {
                if (method.getName().equals("cleanup")) {
                    var context = new MethodContext(method); int ordinal = 0;
                    for (int i = 0; i < context.code().getInstructions().size(); i++) {
                        var insn = context.code().getInstructions().get(i);
                        if (!(insn instanceof ReferenceInstruction ref) || !(ref.getReference() instanceof MethodReference target)
                                || !Signatures.of(target).equals(SIGNATURE)) continue;
                        ordinal++;
                        if (!mode.equals("first") && !mode.equals("unknown-first") && ordinal == 1 || mode.equals("first") && ordinal == 2) continue;
                        int[] args = ConstantEvaluator.arguments(insn);
                        context.code().replaceInstruction(i, new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, args[0], args[1], 0, 0, 0, proxy));
                    }
                    method = context.finish();
                }
                rewritten.add(method);
            }
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), cls.getSourceFile(),
                    cls.getAnnotations(), cls.getFields(), rewritten));
        }
        classes.add(proxyClass(proxy.getDefiningClass(), methods));
        if (mode.equals("nested")) {
            b = new MethodImplementationBuilder(3);
            b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 1, new ImmutableTypeReference("Ljava/lang/String;")));
            b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 2, new ImmutableTypeReference("Ljava/lang/String;")));
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 1, 2, 0, 0, 0, FOG));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
            classes.add(proxyClass(inner.getDefiningClass(), List.of(proxyMethod(inner.getDefiningClass(), inner.getName(), inner.getParameterTypes(), inner.getReturnType(), b.getMethodImplementation()))));
        }
        return new ImmutableDexFile(input.getOpcodes(), classes);
    }
    @Test public void recordedProxyPathsShareLeafCompletionAndKeepUnknownEffectsAndInitialization() throws Exception {
        for (String mode : List.of("plain", "first", "nested", "effects", "initializer", "throws", "unknown-first")) {
            var result = cleanupStrings(cleanupProxyFixture(mode), true);
            assertEquals(mode, 0, result.failedMethods());
            assertTrue(mode, result.methods().stream().allMatch(DexEngine.MethodReport::converged));
            Method caller = new DexContext(result.dex()).methods().get("Lsample/Test;->cleanup(I)Ljava/lang/String;");
            long calls = 0, proxies = 0;
            for (var i : caller.getImplementation().getInstructions())
                if (i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m
                        && (Signatures.of(m).equals(SIGNATURE) || m.getDefiningClass().equals("Lsample/Forwarder;"))) {
                    calls++; if (m.getDefiningClass().equals("Lsample/Forwarder;")) proxies++;
                }
            assertEquals(mode, List.of("plain", "first", "nested").contains(mode) ? 1 : 2, calls);
            assertEquals(mode, mode.equals("plain") || mode.equals("nested") ? 0 : mode.equals("unknown-first") ? 2 : 1, proxies);
            Path file = java.nio.file.Files.createTempFile("proxy-cleanup-", ".dex");
            try { java.nio.file.Files.delete(file); DexFiles.write(file, result.dex()); assertEquals(mode, 0, cleanupStrings(DexFiles.read(file), true).changedMethods()); }
            finally { java.nio.file.Files.deleteIfExists(file); }
        }
    }
    @Test public void explicitCleanupRemovesDecodedCallsAndKeepsFirstSuccessAndBusinessEffects() throws Exception {
        for (String mode : List.of("straight", "dead", "range", "field-initialized", "protected", "branch-both", "exception")) {
            DexFile input = cleanupFixture(mode); var result = cleanupStrings(input, true);
            assertEquals(mode, 0, result.failedMethods()); assertTrue(mode, result.methods().stream().allMatch(DexEngine.MethodReport::converged));
            assertEquals(mode, mode.equals("branch-both") || mode.equals("exception") ? 2 : 1, cleanupCalls(result.dex()));
            Method caller = new DexContext(result.dex()).methods().get("Lsample/Test;->cleanup(I)Ljava/lang/String;");
            assertTrue(mode, java.util.stream.StreamSupport.stream(caller.getImplementation().getInstructions().spliterator(), false)
                    .anyMatch(i -> i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m && m.getName().equals("touch")));
            Path file = java.nio.file.Files.createTempFile("fog-cleanup-", ".dex");
            try { java.nio.file.Files.delete(file); DexFiles.write(file, result.dex()); assertEquals(mode, 0, cleanupStrings(DexFiles.read(file), true).changedMethods()); }
            finally { java.nio.file.Files.deleteIfExists(file); }
        }
    }
    @Test public void unknownInputsUnresolvedMembersAndSynchronizationBlockCleanup() {
        for (String mode : List.of("invalid", "unknown", "unknown-first", "unresolved", "synchronized", "branch-missing")) {
            var result = cleanupStrings(cleanupFixture(mode), true);
            assertEquals(mode, 0, result.failedMethods()); assertEquals(mode, 2, cleanupCalls(result.dex()));
        }
    }
    @Test public void cleanupIsOptInAndDoesNotRemoveGuardedBusinessProxies() throws Exception {
        assertEquals(2, cleanupCalls(cleanupStrings(cleanupFixture("straight"), false).dex()));
        var result = cleanupStrings(proxyFixture("known"), true);
        Method caller = new DexContext(result.dex()).methods().get("Lsample/Test;->proxyCall()Ljava/lang/String;");
        assertTrue(java.util.stream.StreamSupport.stream(caller.getImplementation().getInstructions().spliterator(), false)
                .anyMatch(i -> i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m && m.getDefiningClass().equals("Lsample/Outer;")));
    }
    @Test public void providerValidatesAndAppliesRemovalOption() {
        var provider = new StringDecryptTransformer.Provider();
        var pass = provider.create(new TransformerOptions(Map.of("stringFogXorMethods", List.of(SIGNATURE), "removeDecryptedCalls", true)));
        assertEquals(1, cleanupCalls(new DexEngine(List.of(pass), 10).transform(cleanupFixture("straight")).dex()));
        assertThrows(IllegalArgumentException.class, () -> provider.create(new TransformerOptions(Map.of("removeDecryptedCalls", "true"))));
    }
    private static DexFile harmlessFixture(String mode) {
        DexFile input = mode.equals("proxy") ? cleanupProxyFixture("nested")
                : cleanupFixture(mode.equals("protected") || mode.equals("unknown-first") ? mode : "straight");
        String cell = "Lsample/FogCell;", iface = "Lsample/FogInterface;", bridge = "Lsample/FogBridge;";
        var b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/Object;", "<init>", List.of(), "V")));
        if (mode.equals("constructor-effect")) cleanupEffect(b, "initialize");
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        Method constructor = new ImmutableMethod(cell, "<init>", List.of(), "V", AccessFlags.PUBLIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(), Set.of(), Set.of(), b.getMethodImplementation());
        var cellMethods = new ArrayList<Method>(); cellMethods.add(constructor);
        if (mode.equals("finalizer")) {
            b = new MethodImplementationBuilder(1); cleanupEffect(b, "initialize"); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            cellMethods.add(new ImmutableMethod(cell, "finalize", List.of(), "V", AccessFlags.PROTECTED.getValue(), Set.of(), Set.of(), b.getMethodImplementation()));
        }
        var classes = new ArrayList<ClassDef>();
        classes.add(new ImmutableClassDef(cell, AccessFlags.PUBLIC.getValue() | (mode.equals("abstract-object") ? AccessFlags.ABSTRACT.getValue() : AccessFlags.FINAL.getValue()), "Ljava/lang/Object;", List.of(iface), null, Set.of(), List.of(), cellMethods));
        var interfaceMethods = new ArrayList<Method>();
        interfaceMethods.add(new ImmutableMethod(iface, "unused", List.of(), "V", AccessFlags.PUBLIC.getValue() | AccessFlags.ABSTRACT.getValue(), Set.of(), Set.of(), null));
        if (mode.equals("interface-effect")) {
            b = new MethodImplementationBuilder(0); cleanupEffect(b, "initialize"); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            interfaceMethods.add(proxyMethod(iface, "<clinit>", List.of(), "V", b.getMethodImplementation()));
            b = new MethodImplementationBuilder(1); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            interfaceMethods.add(new ImmutableMethod(iface, "defaultMethod", List.of(), "V", AccessFlags.PUBLIC.getValue(), Set.of(), Set.of(), b.getMethodImplementation()));
        }
        classes.add(new ImmutableClassDef(iface, AccessFlags.PUBLIC.getValue() | AccessFlags.INTERFACE.getValue() | AccessFlags.ABSTRACT.getValue(), "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), interfaceMethods));
        for (ClassDef cls : input.getClasses()) {
            var fields = new ArrayList<Field>(); cls.getFields().forEach(fields::add);
            var methods = new ArrayList<Method>();
            boolean fog = cls.getType().equals("Lsample/Fog;"), dependency = cls.getType().equals("Lsample/FogDependency;");
            for (Method method : cls.getMethods()) {
                if ((fog || dependency) && method.getName().equals("<clinit>")) {
                    if (fog && mode.equals("initializer-effect") || dependency && mode.equals("transitive-effect")) { methods.add(method); continue; }
                    b = new MethodImplementationBuilder(1);
                    for (int table = 0; table < (fog ? 1 : 2); table++) {
                        String type = fog ? "[S" : "[I";
                        var field = new ImmutableField(cls.getType(), "table" + table, type,
                                AccessFlags.PRIVATE.getValue() | AccessFlags.STATIC.getValue() | AccessFlags.FINAL.getValue(), null, Set.of(), Set.of());
                        fields.add(field); Fixtures.integer(b, 0, mode.equals("invalid-table") ? 1 : 2);
                        b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 0, 0, new ImmutableTypeReference(type)));
                        b.addInstruction(new BuilderInstruction31t(Opcode.FILL_ARRAY_DATA, 0, b.getLabel("data" + table)));
                        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT_OBJECT, 0, field));
                    }
                    if (fog) {
                        var field = new ImmutableField(cls.getType(), "impl", cell,
                                AccessFlags.PRIVATE.getValue() | AccessFlags.STATIC.getValue() | AccessFlags.FINAL.getValue(), null, Set.of(), Set.of());
                        fields.add(field);
                        b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 0, new ImmutableTypeReference(cell)));
                        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0, constructor));
                        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT_OBJECT, 0, field));
                    }
                    b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
                    for (int table = 0; table < (fog ? 1 : 2); table++) {
                        b.addLabel("data" + table); b.addInstruction(new BuilderArrayPayload(fog ? 2 : 4, List.of(7, 11)));
                    }
                    method = proxyMethod(cls.getType(), "<clinit>", List.of(), "V", b.getMethodImplementation());
                } else if (fog && method.getName().equals("decrypt") && (mode.equals("transitive-effect") || mode.startsWith("virtual"))) {
                    var context = new MethodContext(method);
                    context.code().replaceInstruction(0, new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                            new ImmutableMethodReference(bridge, "read", List.of(), "I")));
                    context.code().addInstruction(1, new BuilderInstruction11x(Opcode.MOVE_RESULT, 0)); method = context.finish();
                }
                methods.add(method);
            }
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(), fields, methods));
        }
        if (mode.equals("transitive-effect")) {
            b = new MethodImplementationBuilder(1);
            b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, new ImmutableFieldReference("Lsample/FogDependency;", "loaded", "I")));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
            classes.add(proxyClass(bridge, List.of(proxyMethod(bridge, "read", List.of(), "I", b.getMethodImplementation()))));
        } else if (mode.startsWith("virtual")) {
            String child = "Lsample/FogChild;", deep = "Lsample/FogDeepDependency;";
            var baseConstructor = new ImmutableMethodReference(bridge, "<init>", List.of(), "V");
            b = new MethodImplementationBuilder(1);
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0,
                    new ImmutableMethodReference("Ljava/lang/Object;", "<init>", List.of(), "V")));
            b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            var baseMethods = new ArrayList<Method>();
            baseMethods.add(new ImmutableMethod(bridge, "<init>", List.of(), "V", AccessFlags.PUBLIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(), Set.of(), Set.of(), b.getMethodImplementation()));
            b = new MethodImplementationBuilder(2);
            b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, new ImmutableFieldReference(mode.equals("virtual-effect") ? deep : "Lsample/FogDependency;", "loaded", "I")));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
            var read = new ImmutableMethod(bridge, "value", List.of(), "I", AccessFlags.PUBLIC.getValue(), Set.of(), Set.of(), b.getMethodImplementation());
            baseMethods.add(read);
            b = new MethodImplementationBuilder(2);
            if (mode.equals("virtual-join")) {
                Fixtures.integer(b, 1, 1);
                b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 1, b.getLabel("base")));
                b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 0, new ImmutableTypeReference(child)));
                b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0, new ImmutableMethodReference(child, "<init>", List.of(), "V")));
                Fixtures.go(b, "join"); b.addLabel("base");
            }
            b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 0, new ImmutableTypeReference(bridge)));
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0, baseConstructor));
            b.addLabel("join");
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0, read));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
            baseMethods.add(proxyMethod(bridge, "read", List.of(), "I", b.getMethodImplementation()));
            classes.add(proxyClass(bridge, baseMethods));
            if (!mode.equals("virtual")) {
                var deepField = new ImmutableField(deep, "loaded", "I", AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(), new ImmutableIntEncodedValue(1), Set.of(), Set.of());
                b = new MethodImplementationBuilder(0); cleanupEffect(b, "initializeDependency"); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
                classes.add(new ImmutableClassDef(deep, AccessFlags.PUBLIC.getValue(), "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(deepField), List.of(proxyMethod(deep, "<clinit>", List.of(), "V", b.getMethodImplementation()))));
            }
            if (mode.equals("virtual-join")) {
                b = new MethodImplementationBuilder(1);
                b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0, baseConstructor));
                b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
                var childConstructor = new ImmutableMethod(child, "<init>", List.of(), "V", AccessFlags.PUBLIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(), Set.of(), Set.of(), b.getMethodImplementation());
                b = new MethodImplementationBuilder(2);
                b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, new ImmutableFieldReference(deep, "loaded", "I")));
                b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
                classes.add(new ImmutableClassDef(child, AccessFlags.PUBLIC.getValue(), bridge, List.of(), null, Set.of(), List.of(), List.of(childConstructor,
                        new ImmutableMethod(child, "value", List.of(), "I", AccessFlags.PUBLIC.getValue(), Set.of(), Set.of(), b.getMethodImplementation()))));
            }
        }
        return new ImmutableDexFile(input.getOpcodes(), classes);
    }
    @Test public void harmlessInitializationAllowsFirstDirectProtectedAndProxyCallsToDisappear() throws Exception {
        for (String mode : List.of("tables", "protected", "proxy", "unknown-first", "virtual")) {
            DexFile input = harmlessFixture(mode); var result = cleanupStrings(input, true);
            assertEquals(mode, 0, result.failedMethods()); assertTrue(mode, result.methods().stream().allMatch(DexEngine.MethodReport::converged));
            assertEquals(mode, mode.equals("unknown-first") ? 1 : 0, cleanupCalls(result.dex()));
            var caller = new DexContext(result.dex()).methods().get("Lsample/Test;->cleanup(I)Ljava/lang/String;");
            for (var insn : caller.getImplementation().getInstructions()) if (insn instanceof ReferenceInstruction ref && ref.getReference() instanceof MethodReference target)
                assertFalse(mode, target.getDefiningClass().equals("Lsample/Forwarder;") || target.getDefiningClass().equals("Lsample/Nested;"));
            assertEquals(mode, 2, cleanupCalls(cleanupStrings(input, false).dex()) + (mode.equals("proxy") ? 1 : 0));
            Path file = java.nio.file.Files.createTempFile("harmless-initialization-", ".dex");
            try { java.nio.file.Files.delete(file); DexFiles.write(file, result.dex()); assertEquals(mode, 0, cleanupStrings(DexFiles.read(file), true).changedMethods()); }
            finally { java.nio.file.Files.deleteIfExists(file); }
        }
    }
    @Test public void businessInitializersConstructorsInterfacesAndFinalizersKeepFirstDecryption() {
        for (String mode : List.of("initializer-effect", "constructor-effect", "transitive-effect", "interface-effect", "finalizer", "virtual-effect", "virtual-join", "abstract-object", "invalid-table")) {
            var result = cleanupStrings(harmlessFixture(mode), true);
            assertEquals(mode, 0, result.failedMethods()); assertEquals(mode, 1, cleanupCalls(result.dex()));
        }
    }
    public static void main(String[] args) throws Exception {
        Path folder = Path.of(args[0]); java.nio.file.Files.createDirectories(folder);
        for (String mode : List.of("straight", "dead", "range", "field-initialized", "protected", "branch-both", "branch-missing", "exception", "unknown", "unknown-first", "invalid")) {
            DexFile input = cleanupFixture(mode); DexFiles.write(folder.resolve(mode + "-original.dex"), input);
            DexFiles.write(folder.resolve(mode + "-cleaned.dex"), cleanupStrings(input, true).dex());
        }
        for (String mode : List.of("plain", "first", "nested", "effects", "initializer", "throws", "unknown-first")) {
            DexFile input = cleanupProxyFixture(mode); DexFiles.write(folder.resolve("proxy-" + mode + "-original.dex"), input);
            DexFiles.write(folder.resolve("proxy-" + mode + "-cleaned.dex"), cleanupStrings(input, true).dex());
        }
        for (String mode : List.of("tables", "protected", "proxy", "unknown-first", "initializer-effect", "constructor-effect", "transitive-effect", "interface-effect", "virtual", "virtual-effect", "virtual-join")) {
            DexFile input = harmlessFixture(mode); DexFiles.write(folder.resolve("init-" + mode + "-original.dex"), input);
            DexFiles.write(folder.resolve("init-" + mode + "-cleaned.dex"), cleanupStrings(input, true).dex());
        }
    }
    private static String fogText(String text, int key) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < bytes.length; i++) bytes[i] ^= (byte) key;
        return Base64.getEncoder().encodeToString(bytes);
    }
    private static Method branchFixture(String mode) {
        int registers = mode.equals("limit") ? 300 : mode.equals("unknown") ? 6 : 5;
        var b = new MethodImplementationBuilder(registers);
        if (mode.equals("limit")) b.addInstruction(new BuilderInstruction22x(Opcode.MOVE_FROM16, 4, 299));
        b.addLabel("start");
        Fixtures.string(b, 1, "AA==");
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 4, b.getLabel("other")));
        Fixtures.string(b, 0, fogText("✅", 0));
        Fixtures.go(b, "join");
        b.addLabel("other");
        if (mode.equals("correlated")) Fixtures.string(b, 1, "AQ==");
        if (mode.equals("unknown")) b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 0, 5));
        else Fixtures.string(b, 0, mode.equals("invalid") ? "!" : fogText(mode.equals("same") ? "✅" : "❌", mode.equals("correlated") ? 1 : 0));
        b.addLabel("join");
        int arg = 0;
        if (mode.equals("moves")) {
            b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 2, 0));
            b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 2, new ImmutableTypeReference("Ljava/lang/String;")));
            arg = 2;
        }
        b.addLabel("call");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, arg, 1, 0, 0, 0,
                new ImmutableMethodReference("Lsample/Fog;", "decrypt", List.of("Ljava/lang/String;", "Ljava/lang/String;"), "Ljava/lang/String;")));
        b.addLabel("end");
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        if (mode.equals("protected") || mode.equals("mixed-protection")) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
            Fixtures.string(b, 0, "caught"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
            b.addCatch("Ljava/lang/Exception;", b.getLabel(mode.equals("protected") ? "start" : "call"), b.getLabel("end"), b.getLabel("handler"));
        }
        List<ImmutableMethodParameter> params = new ArrayList<>();
        params.add(new ImmutableMethodParameter("I", Set.of(), null));
        if (mode.equals("unknown")) params.add(new ImmutableMethodParameter("Ljava/lang/String;", Set.of(), null));
        return Fixtures.method("branchCall", params, "Ljava/lang/String;", b.getMethodImplementation());
    }
    private static String executeBranch(Method method, int value) {
        var graph = new CodeGraph(method.getImplementation());
        Constants state = new Constants(); state.put(graph.registers() - 1, value);
        for (int pc = 0, budget = 0; budget++ < 100; ) {
            var insn = graph.at(pc);
            if (insn.getOpcode() == Opcode.RETURN_OBJECT)
                return (String) state.get(((org.jf.dexlib2.iface.instruction.OneRegisterInstruction) insn).getRegisterA());
            if (insn.getOpcode() == Opcode.INVOKE_STATIC) {
                List<Object> args = new ArrayList<>();
                for (int register : ConstantEvaluator.arguments(insn)) args.add(state.get(register));
                state.result(new StringFogXorDecoder(SIGNATURE).decode(SIGNATURE, args).orElseThrow());
            } else ConstantEvaluator.step(insn, state);
            List<Integer> next = ConstantBranches.successors(graph, pc, state);
            assertEquals(1, next.size()); pc = next.get(0);
        }
        throw new AssertionError("Branch probe did not return");
    }
    @Test public void restoresCorrelatedBranchStringsAndPreservesSelectionAndCalls() throws Exception {
        for (String mode : List.of("simple", "correlated", "moves", "protected", "same")) {
            Method input = branchFixture(mode);
            var result = decryptProxies(Fixtures.dex(input));
            assertEquals(mode, 0, result.failedMethods()); assertEquals(mode, 1, result.changedMethods());
            Method output = Fixtures.first(result.dex());
            for (int flag : new int[]{0, 1, -1}) {
                assertEquals(mode, flag == 0 && !mode.equals("same") ? "❌" : "✅", executeBranch(input, flag));
                assertEquals(mode, executeBranch(input, flag), executeBranch(output, flag));
            }
            int calls = 0;
            for (var i : output.getImplementation().getInstructions()) if (i.getOpcode() == Opcode.INVOKE_STATIC) calls++;
            assertEquals(1, calls);
            assertEquals(input.getImplementation().getTryBlocks().size(), output.getImplementation().getTryBlocks().size());
            Path file = java.nio.file.Files.createTempFile("fog-branches-", ".dex");
            try {
                java.nio.file.Files.delete(file); DexFiles.write(file, result.dex());
                assertEquals(mode, 0, decryptProxies(DexFiles.read(file)).changedMethods());
            } finally { java.nio.file.Files.deleteIfExists(file); }
        }
    }
    @Test public void retainsBranchesWithUnknownInvalidOrDifferentlyProtectedInputs() {
        for (String mode : List.of("unknown", "invalid", "mixed-protection", "limit")) {
            var result = decryptProxies(Fixtures.dex(branchFixture(mode)));
            assertEquals(mode, 0, result.failedMethods()); assertEquals(mode, 0, result.changedMethods());
        }
    }
    private static DexEngine.Result decryptProxies(DexFile dex) {
        return new DexEngine(List.of(new StringDecryptTransformer(List.of(new StringFogXorDecoder(SIGNATURE)))), 5).transform(dex);
    }
    private static Method proxyMethod(String owner, String name, List<String> parameters, String returns, MethodImplementation code) {
        int flags = AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue();
        if (name.startsWith("<")) flags |= AccessFlags.CONSTRUCTOR.getValue();
        return new ImmutableMethod(owner, name, parameters.stream().map(p -> new ImmutableMethodParameter(p, Set.of(), null)).toList(),
                returns, flags, Set.of(), Set.of(), code);
    }
    private static ClassDef proxyClass(String owner, List<Method> methods) {
        return new ImmutableClassDef(owner, AccessFlags.PUBLIC.getValue(), "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), methods);
    }
    private static DexFile proxyFixture(String mode) throws Exception {
        var source = DexFiles.read(Path.of(StringFogXorTest.class.getResource("/np-batch3/hide-methods.dex").toURI()));
        var dex = new DexContext(source);
        Method guard = dex.methods().values().stream().filter(m -> {
            if (m.getImplementation() == null || !m.getParameterTypes().isEmpty() || !m.getReturnType().equals("I")) return false;
            var g = new CodeGraph(m.getImplementation());
            return g.size() == 4 && g.at(0).getOpcode() == Opcode.CONST && g.at(1).getOpcode() == Opcode.SGET
                    && g.at(2).getOpcode() == Opcode.XOR_INT_2ADDR;
        }).findFirst().orElseThrow();
        var args = List.of("Ljava/lang/Object;", "Ljava/lang/Object;");
        var outer = new ImmutableMethodReference("Lsample/Outer;", "decode", args, "Ljava/lang/String;");
        var inner = new ImmutableMethodReference("Lsample/Inner;", "decode", args, "Ljava/lang/String;");
        var alias = new ImmutableMethodReference("Lsample/Outer;", "guard", List.of(), "I");
        var touch = new ImmutableMethodReference("LProxyStringProbe;", "touch", List.of(), "V");
        var init = new ImmutableMethodReference("LProxyStringProbe;", "initialize", List.of(), "V");
        var b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, mode.equals("guard-cycle") ? alias : guard));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        Method guardAlias = proxyMethod("Lsample/Outer;", "guard", List.of(), "I", b.getMethodImplementation());
        b = new MethodImplementationBuilder(3);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                mode.equals("unknown") ? new ImmutableMethodReference("LProxyStringProbe;", "unknownGuard", List.of(), "I")
                        : mode.equals("alias") || mode.equals("guard-cycle") ? alias : guard));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("fallback")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 1, 2, 0, 0, 0, mode.equals("cycle") ? outer : inner));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        b.addLabel("fallback"); Fixtures.integer(b, 0, 0); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        Method outerMethod = proxyMethod("Lsample/Outer;", "decode", args, "Ljava/lang/String;", b.getMethodImplementation());
        b = new MethodImplementationBuilder(3);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, touch));
        if (mode.equals("wrong-cast")) b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 1, new ImmutableTypeReference("Ljava/lang/StringBuilder;")));
        b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 1, new ImmutableTypeReference("Ljava/lang/String;")));
        b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 2, new ImmutableTypeReference("Ljava/lang/String;")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 1, 2, 0, 0, 0,
                new ImmutableMethodReference("Lsample/Fog;", "decrypt", List.of("Ljava/lang/String;", "Ljava/lang/String;"), "Ljava/lang/String;")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        Method innerMethod = proxyMethod("Lsample/Inner;", "decode", args, "Ljava/lang/String;", b.getMethodImplementation());
        b = new MethodImplementationBuilder(0);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, init));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        List<ClassDef> classes = new ArrayList<>(source.getClasses());
        classes.add(proxyClass("Lsample/Outer;", List.of(outerMethod, guardAlias, proxyMethod("Lsample/Outer;", "<clinit>", List.of(), "V", b.getMethodImplementation()))));
        classes.add(proxyClass("Lsample/Inner;", List.of(innerMethod, proxyMethod("Lsample/Inner;", "<clinit>", List.of(), "V", b.getMethodImplementation()))));
        int first = mode.equals("range") ? 16 : 0;
        b = new MethodImplementationBuilder(mode.equals("range") ? 18 : 3);
        if (mode.equals("unknown-arg")) b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, first, 2));
        else Fixtures.string(b, first, mode.equals("sample-literal") ? "HhsgAnFGHylaXh8j\n" : mode.equals("chain") ? "YUdWc2JHOD0=" : "aGVsbG8=");
        Fixtures.string(b, first + 1, mode.equals("sample-literal") ? "WXpNZzUja0w5KnBRMiF4Ug==\n" : "AA==");
        b.addLabel("start");
        b.addInstruction(mode.equals("range") ? new BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, first, 2, outer)
                : new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, first, first + 1, 0, 0, 0, outer));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        if (mode.equals("chain")) {
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 0, 1, 0, 0, 0, outer));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        }
        b.addLabel("end"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        if (mode.equals("protected")) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
            Fixtures.string(b, 0, "caught"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
            b.addCatch("Ljava/lang/Throwable;", b.getLabel("start"), b.getLabel("end"), b.getLabel("handler"));
        }
        List<Method> callers = new ArrayList<>();
        callers.add(Fixtures.method("proxyCall", mode.equals("unknown-arg") ? List.of(new ImmutableMethodParameter("Ljava/lang/Object;", Set.of(), null)) : List.of(), "Ljava/lang/String;", b.getMethodImplementation()));
        if (mode.equals("mutated")) {
            var field = ((ReferenceInstruction) new CodeGraph(guard.getImplementation()).at(1)).getReference();
            int guardKey = ((org.jf.dexlib2.iface.instruction.NarrowLiteralInstruction) new CodeGraph(guard.getImplementation()).at(0)).getNarrowLiteral();
            b = new MethodImplementationBuilder(1); Fixtures.integer(b, 0, guardKey);
            b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, field)); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            callers.add(Fixtures.method("mutate", List.of(), "V", b.getMethodImplementation()));
        }
        classes.add(proxyClass("Lsample/Test;", callers));
        return new ImmutableDexFile(source.getOpcodes(), classes);
    }
    private static Method handlerFixture(boolean overwriteKey) {
        var b = new MethodImplementationBuilder(3);
        Fixtures.string(b, 0, "aGVsbG8="); Fixtures.string(b, 1, "AA==");
        b.addLabel("start");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("LStringValueProbe;", "touch", List.of(), "V")));
        b.addLabel("end");
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("join")));
        b.addLabel("handler");
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 2));
        if (overwriteKey) Fixtures.string(b, 1, "AQ==");
        b.addLabel("join");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 0, 1, 0, 0, 0,
                new ImmutableMethodReference("Lsample/Fog;", "decrypt", List.of("Ljava/lang/String;", "Ljava/lang/String;"), "Ljava/lang/String;")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        b.addCatch("Ljava/lang/Exception;", b.getLabel("start"), b.getLabel("end"), b.getLabel("handler"));
        return Fixtures.method("handlers", List.of(), "Ljava/lang/String;", b.getMethodImplementation());
    }
    private static Method castFixture(String type, boolean unknown) {
        var b = new MethodImplementationBuilder(4);
        if (unknown) b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 0, 3));
        else Fixtures.string(b, 0, "aGVsbG8=");
        Fixtures.string(b, 1, "AA==");
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 2, 0));
        b.addLabel("start");
        b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 2, new ImmutableTypeReference(type)));
        if (!type.equals("Ljava/lang/String;"))
            b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 2, new ImmutableTypeReference("Ljava/lang/String;")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 2, 1, 0, 0, 0,
                new ImmutableMethodReference("Lsample/Fog;", "decrypt", List.of("Ljava/lang/String;", "Ljava/lang/String;"), "Ljava/lang/String;")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        b.addLabel("end");
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        b.addLabel("handler");
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
        Fixtures.string(b, 0, "caught");
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        b.addCatch("Ljava/lang/Exception;", b.getLabel("start"), b.getLabel("end"), b.getLabel("handler"));
        return Fixtures.method("cast", unknown ? List.of(new ImmutableMethodParameter("Ljava/lang/Object;", Set.of(), null)) : List.of(),
                "Ljava/lang/String;", b.getMethodImplementation());
    }
}
