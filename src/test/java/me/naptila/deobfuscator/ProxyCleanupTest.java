package me.naptila.deobfuscator;

import java.nio.file.*;
import java.util.*;

import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.report.JsonReport;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import me.naptila.deobfuscator.transformers.np.methodhiding.MethodHidingTransformer.Cleanup;
import me.naptila.deobfuscator.transformers.np.methodhiding.MethodHidingTransformer;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.jf.dexlib2.immutable.value.*;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class ProxyCleanupTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    MethodHidingTest fixture;
    static final String OWNER = MethodHidingTest.PROXY, CALLER = MethodHidingTest.CALLER;
    static final ImmutableMethodReference PROXY = new ImmutableMethodReference(OWNER, "proxy", List.of(), "Ljava/lang/String;");
    static final String SIGNATURE = Signatures.of(PROXY);
    @Before public void load() throws Exception { fixture = new MethodHidingTest(); fixture.load(); }
    @Test public void featureSchedulesDefinitionCleanupWithItsOwnOptions() {
        var options = new TransformerOptions(Map.of("assumeClosedWorld", true));
        var app = new Deobfuscator(TransformerRegistry.discover());
        var specs = List.of(new TransformerSpec("np.method-hiding", options));
        var result = app.transform(source(false), specs, 20);
        assertEquals("deleted", decision(result).action());
        assertNull(new DexContext(result.dex()).methods().get(SIGNATURE));
        specs = List.of(new TransformerSpec("np.method-hiding", options.with("keepMethods", List.of(SIGNATURE))));
        result = app.transform(source(false), specs, 20);
        assertEquals("retained", decision(result).action());
        assertTrue(decision(result).reasons().contains("EXPLICIT_KEEP"));
    }
    DexFile source(boolean protectedCall) {
        var full = fixture.fixture("literal", protectedCall);
        return new ImmutableDexFile(full.getOpcodes(), full.getClasses().stream().filter(c -> !c.getType().startsWith("Ldev/deobfuscator/fixture/") || c.getType().equals(fixture.guard.getDefiningClass())).toList());
    }
    DexEngine.Result clean(DexFile input, boolean closed) {
        return new DexEngine(List.of(new MethodHidingTransformer(), new Cleanup(closed, List.of())), 20).transform(input);
    }
    TransformationEvidence.Decision decision(DexEngine.Result result) {
        return result.evidence().decisions().stream().filter(d -> d.method().equals(SIGNATURE)).findFirst().orElseThrow();
    }
    Method make(String owner, String name, MethodImplementationBuilder b) {
        return fixture.method(owner, name, List.of(), "V", 9, b.getMethodImplementation());
    }
    DexFile add(DexFile input, String owner, Method method) {
        List<ClassDef> classes = new ArrayList<>();
        for (ClassDef cls : input.getClasses()) {
            if (!cls.getType().equals(owner)) { classes.add(cls); continue; }
            List<Method> methods = new ArrayList<>(); cls.getMethods().forEach(methods::add); methods.add(method);
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
        }
        return new ImmutableDexFile(input.getOpcodes(), classes);
    }
    @Test public void defaultRetainsPublicEntryAndClosedWorldDeletesOnlyRecordedDefinition() throws Exception {
        DexFile input = source(false); var conservative = clean(input, false);
        assertEquals("retained", decision(conservative).action()); assertTrue(decision(conservative).reasons().contains("EXTERNAL_ENTRY_NOT_EXCLUDED"));
        assertEquals(1, conservative.evidence().replacements().size());
        var closed = clean(input, true); assertEquals("deleted", decision(closed).action());
        assertNull(new DexContext(closed.dex()).methods().get(SIGNATURE));
        assertEquals(input.getClasses().size(), closed.dex().getClasses().size());
        assertEquals(new DexContext(input).fields().keySet(), new DexContext(closed.dex()).fields().keySet());
        assertEquals("\ud800X\udc00\ud83d\ude42", Fixtures.execute(fixture.getCaller(closed.dex(), false), 0));
        var parsed = new org.yaml.snakeyaml.Yaml().load(JsonReport.write(closed, false)); assertTrue(parsed instanceof Map);
        Path file = directory.getRoot().toPath().resolve("clean.dex"); DexFiles.write(file, closed.dex());
        var second = clean(DexFiles.read(file), true); assertEquals(0, second.dexEdits()); assertEquals(0, second.changedMethods());
        assertTrue(second.evidence().candidates().isEmpty());
    }
    @Test public void cleanupAloneDoesNotRecognizeAlreadySimplifiedMethods() {
        var restored = new DexEngine(List.of(new MethodHidingTransformer()), 20).transform(source(false));
        var result = new DexEngine(List.of(new Cleanup(true, List.of())), 20).transform(restored.dex());
        assertTrue(result.evidence().candidates().isEmpty()); assertEquals(0, result.dexEdits());
        assertNotNull(new DexContext(result.dex()).methods().get(SIGNATURE));
    }
    @Test public void unrecordedLookalikeAndInitializersArePreserved() {
        var b = new MethodImplementationBuilder(1); Fixtures.string(b, 0, "ordinary"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        Method ordinary = fixture.method(OWNER, "ordinary", List.of(), "Ljava/lang/String;", 9, b.getMethodImplementation());
        DexFile input = add(source(false), OWNER, ordinary);
        b = new MethodImplementationBuilder(1); Fixtures.integer(b, 0, 73); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        Method init = fixture.method(CALLER, "<clinit>", List.of(), "V", 8 | AccessFlags.CONSTRUCTOR.getValue(), b.getMethodImplementation());
        input = add(input, CALLER, init); var result = clean(input, true); DexContext output = new DexContext(result.dex());
        assertNotNull(output.methods().get(Signatures.of(ordinary))); assertEquals("deleted", decision(result).action());
        assertEquals(MethodFingerprint.of(new DexContext(input), init), MethodFingerprint.of(output, output.methods().get(Signatures.of(init))));
    }
    @Test public void protectedRemainingCallAndExplicitKeepPreventDeletion() {
        assertEquals("deleted", decision(clean(source(true), true)).action());
        var protectedResult = new DexEngine(List.of(new MethodHidingTransformer(List.of(), false), new Cleanup(true, List.of())), 20)
                .transform(source(true));
        assertEquals("retained", decision(protectedResult).action()); assertTrue(decision(protectedResult).reasons().contains("REFERENCED_BY_RETAINED_METHOD"));
        var kept = new DexEngine(List.of(new MethodHidingTransformer(), new Cleanup(true, List.of(SIGNATURE))), 20).transform(source(false));
        assertTrue(decision(kept).reasons().contains("EXPLICIT_KEEP")); assertEquals("retained", decision(kept).action());
    }
    @Test public void parameterDescriptorsMatchAcrossDefinitionAndInstructionRepresentations() {
        DexFile input = fixture.fixture("wide", true);
        var ref = new ImmutableMethodReference(OWNER, "proxy", List.of("J"), "J");
        DexContext original = new DexContext(input); Method method = original.methods().get(Signatures.of(ref));
        assertTrue(MethodReferences.mayResolveTo(original, ref, method));
        var result = new DexEngine(List.of(new MethodHidingTransformer(List.of(), false), new Cleanup(true, List.of())), 20).transform(input);
        var output = new DexContext(result.dex());
        assertNotNull(output.methods().get(Signatures.of(ref)));
        assertTrue(result.evidence().decisions().stream().anyMatch(d -> d.method().equals(Signatures.of(ref))
                && d.action().equals("retained") && d.reasons().contains("REFERENCED_BY_RETAINED_METHOD")));
    }
    @Test public void rollbackAndRoundLimitNeverCommitReplacementEvidence() {
        for (boolean rollback : List.of(true, false)) {
            DexPass trouble = new DexPass() {
                public String id() { return "test.incomplete"; }
                public PassResult run(MethodContext m) {
                    if (!m.original().getDefiningClass().equals(CALLER)) return PassResult.unchanged();
                    if (rollback) throw new IllegalStateException("forced rollback");
                    return PassResult.changed(1);
                }
            };
            var result = new DexEngine(List.of(new MethodHidingTransformer(), trouble, new Cleanup(true, List.of())), 2).transform(source(false));
            assertEquals("retained", decision(result).action());
            assertTrue(decision(result).reasons().contains("INCOMPLETE_METHOD_TRANSACTIONS")); assertTrue(result.evidence().replacements().isEmpty());
            assertFalse(result.evidence().incompleteMethods().isEmpty());
        }
    }
    @Test public void lateLinkIsCheckedBeforeRemovalEvenWithCleanupListedFirst() {
        class Link implements DexPass, DexFinalizer {
            public String id() { return "test.link"; } public Phase phase() { return Phase.LINK; }
            public PassResult run(MethodContext m) { return PassResult.unchanged(); }
            public Result finish(DexContext original, DexFile rewritten) {
                var b = new MethodImplementationBuilder(0); b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, PROXY)); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
                return new Result(add(rewritten, CALLER, make(CALLER, "linked", b)), PassResult.changed(1));
            }
        }
        var result = new DexEngine(List.of(new Cleanup(true, List.of()), new MethodHidingTransformer(), new Link()), 20).transform(source(false));
        assertEquals(List.of("test.link", "np.method-hiding.cleanup"), result.dexSteps().stream().map(DexEngine.DexStep::pass).toList());
        assertEquals("retained", decision(result).action()); assertTrue(decision(result).references().stream().anyMatch(s -> s.contains("linked")));
    }
    @Test public void inheritedAndUnknownSymbolicOwnersRetainProxy() {
        for (String owner : List.of("Lprobe/Child;", "Lunknown/Child;")) {
            var b = new MethodImplementationBuilder(0);
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, new ImmutableMethodReference(owner, "proxy", List.of(), "Ljava/lang/String;")));
            b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            DexFile input = add(source(false), CALLER, make(CALLER, "inherited", b));
            var classes = new ArrayList<ClassDef>(input.getClasses()); classes.add(new ImmutableClassDef("Lprobe/Child;", 1, OWNER, List.of(), null, Set.of(), List.of(), List.of()));
            var result = clean(new ImmutableDexFile(input.getOpcodes(), classes), true); assertEquals("retained", decision(result).action());
        }
    }
    @Test public void nativeReflectionAndMethodNameStringsBlockClosedWorldRemoval() {
        for (String mode : List.of("native", "reflection", "name")) {
            Method method;
            if (mode.equals("native")) method = fixture.method(CALLER, "nativeCall", List.of(), "V", 9 | AccessFlags.NATIVE.getValue(), null);
            else {
                var b = new MethodImplementationBuilder(3);
                if (mode.equals("name")) Fixtures.string(b, 0, "proxy");
                else {
                    b.addInstruction(new BuilderInstruction21c(Opcode.CONST_CLASS, 0, new ImmutableTypeReference(OWNER)));
                    Fixtures.string(b, 1, "computed-name"); Fixtures.integer(b, 2, 0);
                    b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 3, 0, 1, 2, 0, 0,
                            new ImmutableMethodReference("Ljava/lang/Class;", "getDeclaredMethod", List.of("Ljava/lang/String;", "[Ljava/lang/Class;"), "Ljava/lang/reflect/Method;")));
                }
                b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID)); method = make(CALLER, "dynamic", b);
            }
            var result = clean(add(source(false), CALLER, method), true); assertEquals(mode, "retained", decision(result).action());
            assertTrue(decision(result).reasons().contains(mode.equals("name") ? "METHOD_NAME_STRING_PRESENT" : "DYNAMIC_METHOD_ACCESS_NOT_EXCLUDED"));
        }
    }
    @Test public void handlesCallSitesAndNestedEncodedMethodsAreRoots() {
        var handle = new ImmutableMethodHandleReference(MethodHandleType.INVOKE_STATIC, PROXY);
        for (String mode : List.of("handle", "callsite", "annotation", "encodedHandle")) {
            var b = new MethodImplementationBuilder(1);
            if (mode.equals("handle")) b.addInstruction(new BuilderInstruction21c(Opcode.CONST_METHOD_HANDLE, 0, handle));
            if (mode.equals("callsite")) {
                var bootstrap = new ImmutableMethodHandleReference(MethodHandleType.INVOKE_STATIC, new ImmutableMethodReference("Lexternal/Bootstrap;", "link", List.of(), "Ljava/lang/Object;"));
                var site = new ImmutableCallSiteReference("site", bootstrap, "dynamic", new ImmutableMethodProtoReference(List.of(), "V"),
                        List.of(new ImmutableArrayEncodedValue(List.of(new ImmutableMethodHandleEncodedValue(handle)))));
                b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_CUSTOM, 0, 0, 0, 0, 0, 0, site));
            }
            b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID)); Method method = make(CALLER, "metadata", b);
            if (mode.equals("annotation") || mode.equals("encodedHandle")) {
                var value = mode.equals("annotation") ? new ImmutableMethodEncodedValue(PROXY) : new ImmutableMethodHandleEncodedValue(handle);
                var annotation = new ImmutableAnnotation(AnnotationVisibility.RUNTIME, "Lprobe/Metadata;", List.of(new ImmutableAnnotationElement("methods", new ImmutableArrayEncodedValue(List.of(value)))));
                method = new ImmutableMethod(CALLER, "metadata", List.of(), "V", 9, Set.of(annotation), Set.of(), b.getMethodImplementation());
            }
            var result = clean(add(source(false), CALLER, method), true);
            assertEquals(mode, "retained", decision(result).action()); assertTrue(decision(result).reasons().contains("METADATA_OR_HANDLE_REFERENCE"));
        }
    }
    DexFile replace(DexFile input, Method replacement) {
        List<ClassDef> classes = new ArrayList<>();
        for (ClassDef cls : input.getClasses()) {
            List<Method> methods = new ArrayList<>();
            for (Method method : cls.getMethods()) methods.add(Signatures.of(method).equals(Signatures.of(replacement)) ? replacement : method);
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
        }
        return new ImmutableDexFile(input.getOpcodes(), classes);
    }
    @Test public void unusedProxyComponentsAreRemovedButKeptEntryRetainsItsDependencies() {
        DexFile input = source(false);
        var b = new MethodImplementationBuilder(1); Fixtures.string(b, 0, "business"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        input = replace(input, fixture.method(CALLER, "call", List.of(), "Ljava/lang/String;", 9, b.getMethodImplementation()));
        String target = MethodHidingTest.TARGET;
        Method second = fixture.method(target, "proxyB", List.of(), "Ljava/lang/String;", 9, fixture.proxy("literal").getImplementation());
        input = add(input, target, second);
        b = new MethodImplementationBuilder(0); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        input = add(input, target, fixture.method(target, "<clinit>", List.of(), "V", 8 | AccessFlags.CONSTRUCTOR.getValue(), b.getMethodImplementation()));
        b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, fixture.guard));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("fallback")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, second));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        b.addLabel("fallback"); Fixtures.integer(b, 0, 0); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        input = replace(input, fixture.method(OWNER, "proxy", List.of(), "Ljava/lang/String;", 9, b.getMethodImplementation()));
        var result = clean(input, true);
        Set<String> component = Set.of(SIGNATURE, Signatures.of(second));
        assertEquals(2, result.evidence().decisions().stream().filter(d -> component.contains(d.method()) && d.action().equals("deleted")).count());
        assertNotNull(new DexContext(result.dex()).methods().get(target + "-><clinit>()V"));
        var kept = new DexEngine(List.of(new MethodHidingTransformer(), new Cleanup(true, List.of(SIGNATURE))), 20).transform(input);
        assertEquals(2, kept.evidence().decisions().stream().filter(d -> component.contains(d.method()) && d.action().equals("retained")).count());
        assertTrue(kept.evidence().decisions().stream().filter(d -> d.method().equals(Signatures.of(second))).findFirst().orElseThrow().reasons().contains("REACHABLE_FROM_RETAINED_PROXY"));
    }
    @Test public void finalizerBodyChangesInvalidateTheAcceptedFingerprint() {
        class Change implements DexPass, DexFinalizer {
            public String id() { return "test.change"; }
            public PassResult run(MethodContext m) { return PassResult.unchanged(); }
            public Result finish(DexContext original, DexFile rewritten) {
                var b = new MethodImplementationBuilder(1); Fixtures.string(b, 0, "new body"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
                return new Result(replace(rewritten, fixture.method(OWNER, "proxy", List.of(), "Ljava/lang/String;", 9, b.getMethodImplementation())), PassResult.changed(1));
            }
        }
        var result = new DexEngine(List.of(new MethodHidingTransformer(), new Cleanup(true, List.of()), new Change()), 20).transform(source(false));
        assertEquals("retained", decision(result).action()); assertTrue(decision(result).reasons().contains("OUTPUT_CHANGED_AFTER_TRANSACTION_OR_UNCOMMITTED"));
    }
}
