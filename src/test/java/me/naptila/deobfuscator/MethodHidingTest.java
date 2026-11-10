package me.naptila.deobfuscator;

import java.nio.file.*;
import java.util.*;
import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import me.naptila.deobfuscator.transformers.np.analysis.NpAnalysis;
import me.naptila.deobfuscator.transformers.np.methodhiding.MethodHidingTransformer;
import me.naptila.deobfuscator.transformers.np.analysis.NpHelpers;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.junit.*;
import static org.junit.Assert.*;

public class MethodHidingTest {
    static final String PROXY = "Lprobe/Proxy;", CALLER = "Lprobe/Caller;", TARGET = "Lprobe/Target;";
    static final int PUBLIC_STATIC = AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue();
    DexFile input;
    MethodReference guard;
    @Before public void load() throws Exception {
        input = DexFiles.read(Path.of(getClass().getResource("/np-batch3/hide-methods.dex").toURI()));
        DexContext dex = new DexContext(input);
        for (Method m : dex.methods().values()) {
            if (!m.getParameterTypes().isEmpty() || !m.getReturnType().equals("I") || m.getImplementation() == null) continue;
            CodeGraph g = new CodeGraph(m.getImplementation());
            if (g.size() == 4 && g.at(0).getOpcode() == Opcode.CONST && g.at(1).getOpcode() == Opcode.SGET && g.at(2).getOpcode() == Opcode.XOR_INT_2ADDR) {
                guard = m; break;
            }
        }
        assertNotNull(guard);
    }
    Method method(String owner, String name, List<String> params, String ret, int flags, MethodImplementation code) {
        return new ImmutableMethod(owner, name, params.stream().map(t -> new ImmutableMethodParameter(t, Set.of(), null)).toList(), ret, flags, Set.of(), Set.of(), code);
    }
    Method proxy(String mode) {
        boolean wide = mode.equals("wide");
        var b = new MethodImplementationBuilder(wide ? 4 : 1);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, guard));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("fallback")));
        if (wide) {
            b.addInstruction(new BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, 2, 2, new ImmutableMethodReference(TARGET, "echo", List.of("J"), "J")));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_WIDE, 0));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
        } else if (mode.equals("private-field")) {
            b.addInstruction(new BuilderInstruction21c(Opcode.SGET_OBJECT, 0, new ImmutableFieldReference(TARGET, "secret", "Ljava/lang/String;")));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        } else {
            Fixtures.string(b, 0, "\ud800X\udc00\ud83d\ude42");
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        }
        b.addLabel("fallback");
        if (wide) {
            b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 0, 0));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
        } else { Fixtures.integer(b, 0, 0); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0)); }
        return method(PROXY, "proxy", wide ? List.of("J") : List.of(), wide ? "J" : "Ljava/lang/String;",
                PUBLIC_STATIC | (mode.equals("synchronized") ? AccessFlags.DECLARED_SYNCHRONIZED.getValue() : 0), b.getMethodImplementation());
    }
    Method caller(boolean wide, boolean protectedCall) {
        var b = new MethodImplementationBuilder(wide ? 3 : 1);
        b.addLabel("start");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, wide ? 2 : 0, 1, 2, 0, 0, 0,
                new ImmutableMethodReference(PROXY, "proxy", wide ? List.of("J") : List.of(), wide ? "J" : "Ljava/lang/String;")));
        b.addLabel("end");
        b.addInstruction(new BuilderInstruction11x(wide ? Opcode.MOVE_RESULT_WIDE : Opcode.MOVE_RESULT_OBJECT, 0));
        b.addInstruction(new BuilderInstruction11x(wide ? Opcode.RETURN_WIDE : Opcode.RETURN_OBJECT, 0));
        if (protectedCall) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
            Fixtures.string(b, 0, "caught"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
            b.addCatch(b.getLabel("start"), b.getLabel("end"), b.getLabel("handler"));
        }
        return method(CALLER, "call", wide ? List.of("J") : List.of(), wide ? "J" : "Ljava/lang/String;", PUBLIC_STATIC, b.getMethodImplementation());
    }
    DexFile fixture(String mode, boolean protectedCall) {
        List<ClassDef> classes = new ArrayList<>(input.getClasses());
        List<Method> proxies = new ArrayList<>(List.of(proxy(mode)));
        if (mode.equals("initializer")) {
            var b = new MethodImplementationBuilder(0); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            proxies.add(method(PROXY, "<clinit>", List.of(), "V", AccessFlags.STATIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(), b.getMethodImplementation()));
        }
        classes.add(new ImmutableClassDef(PROXY, AccessFlags.PUBLIC.getValue(), "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), proxies));
        classes.add(new ImmutableClassDef(CALLER, AccessFlags.PUBLIC.getValue(), "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(caller(mode.equals("wide"), protectedCall))));
        var echo = new MethodImplementationBuilder(2); echo.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
        classes.add(new ImmutableClassDef(TARGET, AccessFlags.PUBLIC.getValue(), "Ljava/lang/Object;", List.of(), null, Set.of(),
                List.of(new ImmutableField(TARGET, "secret", "Ljava/lang/String;", AccessFlags.PRIVATE.getValue() | AccessFlags.STATIC.getValue(), null, Set.of(), Set.of())),
                List.of(method(TARGET, "echo", List.of("J"), "J", PUBLIC_STATIC, echo.getMethodImplementation()))));
        return new ImmutableDexFile(input.getOpcodes(), classes);
    }
    DexEngine.Result clean(DexFile source) {
        var r = new Deobfuscator(TransformerRegistry.discover()).transform(source, List.of(new TransformerSpec("np.method-hiding")), 20);
        assertEquals(0, r.failedMethods()); assertTrue(r.methods().stream().allMatch(DexEngine.MethodReport::converged)); return r;
    }
    Method getCaller(DexFile dex, boolean wide) {
        return new DexContext(dex).findMethod(CALLER + "->call(" + (wide ? "J)J" : ")Ljava/lang/String;")).orElseThrow();
    }
    boolean hasProxy(Method method) {
        for (Instruction i : method.getImplementation().getInstructions()) if (i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m && m.getDefiningClass().equals(PROXY)) return true;
        return false;
    }
    @Test public void restoresLiteralCodeUnitsWithoutNamesOrUnicodeConversion() {
        Method output = getCaller(clean(fixture("literal", false)).dex(), false);
        assertFalse(hasProxy(output)); assertEquals("\ud800X\udc00\ud83d\ude42", Fixtures.execute(output, 0));
    }
    @Test public void restoresProtectedCallsByDefaultAndSupportsExplicitOptOut() {
        DexFile source = fixture("literal", true);
        assertFalse(hasProxy(getCaller(clean(source).dex(), false)));
        var protectedResult = new Deobfuscator(TransformerRegistry.discover()).transform(source,
                List.of(new TransformerSpec("np.method-hiding", new TransformerOptions(Map.of("inlineProtected", false)))), 20);
        assertEquals(0, protectedResult.failedMethods());
        assertTrue(hasProxy(getCaller(protectedResult.dex(), false)));
        assertTrue(notes(protectedResult).stream().anyMatch(n -> n.contains("try protection; inlineProtected=false")));
    }
    @Test public void retainsSynchronizationInitializationAndPrivateAccess() {
        for (String mode : List.of("initializer", "synchronized", "private-field"))
            assertTrue(mode, hasProxy(getCaller(clean(fixture(mode, false)).dex(), false)));
    }

    private List<String> notes(DexEngine.Result result) {
        return result.methods().stream().flatMap(m -> m.steps().stream()).flatMap(s -> s.result().notes().stream()).toList();
    }
    private static final String ALIASES = "Lprobe/GuardAliases;";
    private static final ImmutableFieldReference EFFECTS = new ImmutableFieldReference(TARGET, "effects", "I");
    private DexFile layered(String mode) {
        List<ClassDef> classes = new ArrayList<>(input.getClasses());
        List<Method> aliases = new ArrayList<>();
        for (int level = 0; level < 3; level++) {
            var b = new MethodImplementationBuilder(1);
            MethodReference gate = level == 0 || mode.equals("cycle") ? guard
                    : new ImmutableMethodReference(ALIASES, "guard" + (level - 1), List.of(), "I");
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, gate));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
            b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("fallback")));
            MethodReference actual = mode.equals("effectful") ? new ImmutableMethodReference(TARGET, "businessGuard", List.of(), "I")
                    : mode.equals("cycle") ? new ImmutableMethodReference(ALIASES, "guard" + (level == 0 ? 1 : 0), List.of(), "I") : guard;
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, actual));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
            if (mode.equals("arithmetic")) {
                b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, 1));
                b.addInstruction(new BuilderInstruction12x(Opcode.NEG_INT, 0, 0));
                b.addInstruction(new BuilderInstruction12x(Opcode.NOT_INT, 0, 0));
                b.addInstruction(new BuilderInstruction22b(Opcode.OR_INT_LIT8, 0, 0, 1));
            } else if (mode.equals("division") || mode.equals("division-zero")) {
                b.addInstruction(new BuilderInstruction22b(Opcode.DIV_INT_LIT8, 0, 0, mode.equals("division-zero") ? 0 : -1));
            }
            b.addLabel("done"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
            b.addLabel("fallback"); Fixtures.integer(b, 0, 0); Fixtures.go(b, "done");
            aliases.add(method(ALIASES, "guard" + level, List.of(), "I", PUBLIC_STATIC, b.getMethodImplementation()));
        }
        if (mode.contains("initializer")) {
            var b = new MethodImplementationBuilder(0);
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                    new ImmutableMethodReference("LProxyGuardProbe;", "initialize", List.of(), "V")));
            b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            aliases.add(method(ALIASES, "<clinit>", List.of(), "V", AccessFlags.STATIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(), b.getMethodImplementation()));
        }
        var b = new MethodImplementationBuilder(2);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference(ALIASES, "guard2", List.of(), "I")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("fallback")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 1, 0, 0, 0, 0,
                new ImmutableMethodReference(TARGET, "effect", List.of("I"), "I")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        b.addLabel("done"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("fallback"); Fixtures.integer(b, 0, -7); Fixtures.go(b, "done");
        Method hidden = method(PROXY, "hidden", List.of("I"), "I", PUBLIC_STATIC, b.getMethodImplementation());
        b = new MethodImplementationBuilder(2);
        if (mode.equals("repeated-initializer")) b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 1, 0, 0, 0, 0, hidden));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 1, 0, 0, 0, 0, hidden));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        Method caller = method(CALLER, "callInt", List.of("I"), "I", PUBLIC_STATIC, b.getMethodImplementation());
        b = new MethodImplementationBuilder(2);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, EFFECTS));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, 1));
        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, EFFECTS));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 1, 11));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        List<Method> targets = new ArrayList<>(List.of(method(TARGET, "effect", List.of("I"), "I", PUBLIC_STATIC, b.getMethodImplementation())));
        b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, EFFECTS));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, 1));
        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, EFFECTS));
        Fixtures.integer(b, 0, 1); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        targets.add(method(TARGET, "businessGuard", List.of(), "I", PUBLIC_STATIC, b.getMethodImplementation()));
        if (mode.equals("mutated")) {
            var summary = NpAnalysis.of(new DexContext(input)).model().helpers().guards().get(Signatures.of(guard));
            FieldReference field = new DexContext(input).fields().get(summary.field());
            b = new MethodImplementationBuilder(1); Fixtures.integer(b, 0, 0);
            b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, field)); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            targets.add(method(TARGET, "mutate", List.of(), "V", PUBLIC_STATIC, b.getMethodImplementation()));
        }
        classes.add(new ImmutableClassDef(ALIASES, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), aliases));
        classes.add(new ImmutableClassDef(PROXY, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(hidden)));
        classes.add(new ImmutableClassDef(CALLER, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(caller)));
        classes.add(new ImmutableClassDef(TARGET, 1, "Ljava/lang/Object;", List.of(), null, Set.of(),
                List.of(new ImmutableField(TARGET, "effects", "I", PUBLIC_STATIC, null, Set.of(), Set.of())), targets));
        return new ImmutableDexFile(input.getOpcodes(), classes);
    }
    private DexFile largeProxy() {
        List<String> objects = Collections.nCopies(40, "Ljava/lang/Object;"), strings = Collections.nCopies(40, "Ljava/lang/String;");
        var b = new MethodImplementationBuilder(41);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, guard));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("fallback")));
        for (int r = 1; r <= 40; r++) b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, r, new ImmutableTypeReference("Ljava/lang/String;")));
        b.addInstruction(new BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, 1, 40, new ImmutableMethodReference(TARGET, "many", strings, "I")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0)); b.addLabel("done"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("fallback"); Fixtures.integer(b, 0, -7); Fixtures.go(b, "done");
        Method hidden = method(PROXY, "large", objects, "I", PUBLIC_STATIC, b.getMethodImplementation());
        b = new MethodImplementationBuilder(41);
        b.addInstruction(new BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, 1, 40, hidden));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        Method caller = method(CALLER, "callLarge", objects, "I", PUBLIC_STATIC, b.getMethodImplementation());
        b = new MethodImplementationBuilder(41); Fixtures.integer(b, 0, 123); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        Method target = method(TARGET, "many", strings, "I", PUBLIC_STATIC, b.getMethodImplementation());
        List<ClassDef> classes = new ArrayList<>(input.getClasses());
        for (Method m : List.of(hidden, caller, target)) classes.add(new ImmutableClassDef(m.getDefiningClass(), 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(m)));
        return new ImmutableDexFile(input.getOpcodes(), classes);
    }
    @Test public void restoresProxiesWhoseGuardsAreHiddenBehindSeveralLayers() {
        var result = clean(layered("plain"));
        Method caller = new DexContext(result.dex()).findMethod(CALLER + "->callInt(I)I").orElseThrow();
        assertFalse(hasProxy(caller));
        boolean businessCall = false;
        for (Instruction i : caller.getImplementation().getInstructions()) if (i instanceof ReferenceInstruction r
                && r.getReference() instanceof MethodReference m && Signatures.of(m).equals(TARGET + "->effect(I)I")) businessCall = true;
        assertTrue(businessCall);
    }
    @Test public void preservesInitializationCallsWhileUsingTheirProvenGuardResults() {
        var result = clean(layered("initializer"));
        Method caller = new DexContext(result.dex()).findMethod(CALLER + "->callInt(I)I").orElseThrow();
        assertFalse(hasProxy(caller));
        boolean retained = false;
        for (Instruction i : caller.getImplementation().getInstructions()) if (i instanceof ReferenceInstruction r
                && r.getReference() instanceof MethodReference m && m.getDefiningClass().equals(ALIASES)) retained = true;
        assertTrue(retained);
        assertTrue(notes(result).stream().anyMatch(n -> n.contains("proxy class initialization")));
    }
    @Test public void rejectsGuardAliasesWithUnknownEffectsCyclesOrMutableFields() {
        for (String mode : List.of("effectful", "cycle", "mutated", "division-zero")) {
            var result = clean(layered(mode));
            assertTrue(mode, hasProxy(new DexContext(result.dex()).findMethod(CALLER + "->callInt(I)I").orElseThrow()));
        }
    }
    @Test public void restoresIntegerGuardExpressionsAndNonzeroDivision() {
        for (String mode : List.of("arithmetic", "division")) {
            Method caller = new DexContext(clean(layered(mode)).dex()).findMethod(CALLER + "->callInt(I)I").orElseThrow();
            assertFalse(mode, hasProxy(caller));
        }
    }
    @Test public void retainsFirstInitializationAndRestoresRepeatedProxyCalls() {
        Method caller = new DexContext(clean(layered("repeated-initializer")).dex()).findMethod(CALLER + "->callInt(I)I").orElseThrow();
        assertFalse(hasProxy(caller));
        assertEquals(1, ownerCalls(caller, ALIASES));
        assertEquals(2, ownerCalls(caller, TARGET));
    }
    @Test public void retainsUninitializedProxyCallsInFailureHandlers() {
        DexFile source = layered("initializer");
        var b = new MethodImplementationBuilder(1);
        MethodReference alias = new ImmutableMethodReference(ALIASES, "guard2", List.of(), "I");
        b.addLabel("start"); b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, alias));
        b.addLabel("end"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, alias));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addCatch(b.getLabel("start"), b.getLabel("end"), b.getLabel("handler"));
        Method caller = method(CALLER, "retry", List.of(), "I", PUBLIC_STATIC, b.getMethodImplementation());
        List<ClassDef> classes = new ArrayList<>();
        for (ClassDef cls : source.getClasses()) classes.add(cls.getType().equals(CALLER)
                ? new ImmutableClassDef(CALLER, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(caller)) : cls);
        var result = new DexEngine(List.of(new MethodHidingTransformer(List.of(), true)), 20).transform(new ImmutableDexFile(source.getOpcodes(), classes));
        assertEquals(0, result.failedMethods()); assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged));
        assertEquals(2, ownerCalls(new DexContext(result.dex()).findMethod(CALLER + "->retry()I").orElseThrow(), ALIASES));
    }
    private int ownerCalls(Method method, String owner) {
        int count = 0;
        for (Instruction i : method.getImplementation().getInstructions()) if (i instanceof ReferenceInstruction r
                && r.getReference() instanceof MethodReference m && m.getDefiningClass().equals(owner)) count++;
        return count;
    }
    @Test public void restoresLargeRangeProxiesAndKeepsEveryParameterCast() throws Exception {
        var result = clean(largeProxy());
        Path file = Files.createTempFile("np-large-proxy", ".dex");
        try {
            Files.delete(file); DexFiles.write(file, result.dex()); DexFile reread = DexFiles.read(file);
            Method caller = new DexContext(reread).methods().values().stream().filter(m -> m.getDefiningClass().equals(CALLER)).findFirst().orElseThrow();
            assertFalse(hasProxy(caller)); int casts = 0;
            for (Instruction i : caller.getImplementation().getInstructions()) if (i.getOpcode() == Opcode.CHECK_CAST) casts++;
            assertEquals(40, casts);
            assertTrue(caller.getImplementation().getRegisterCount() > 41);
            assertEquals(0, clean(reread).changedMethods());
        } finally { Files.deleteIfExists(file); }
    }
    @Test public void explicitProtectedInliningKeepsTheThrowingLiteralInsideTheHandlerRange() {
        var pass = new MethodHidingTransformer(List.of(), true);
        var result = new DexEngine(List.of(pass), 20).transform(fixture("literal", true));
        assertEquals(0, result.failedMethods());
        Method output = getCaller(result.dex(), false); assertFalse(hasProxy(output));
        CodeGraph graph = new CodeGraph(output.getImplementation());
        assertTrue(graph.at(0).getOpcode().name.startsWith("const-string"));
        assertFalse(graph.protection(0).isEmpty());
        assertEquals(Opcode.MOVE_EXCEPTION, graph.at(graph.handlers(0).get(0)).getOpcode());
    }
    DexFile protectedMemberFixture(boolean protectResult) {
        var proxy = new MethodImplementationBuilder(4);
        proxy.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, guard));
        proxy.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        proxy.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, proxy.getLabel("fallback")));
        proxy.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 2, new ImmutableTypeReference("Ljava/lang/String;")));
        var target = new ImmutableMethodReference(TARGET, "compute", List.of("Ljava/lang/String;", "I"), "I");
        proxy.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 2, 3, 0, 0, 0, target));
        proxy.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        proxy.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        proxy.addLabel("fallback"); Fixtures.integer(proxy, 0, -999); proxy.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        var caller = new MethodImplementationBuilder(8);
        Fixtures.integer(caller, 0, 41); Fixtures.integer(caller, 1, 17); Fixtures.integer(caller, 2, -4);
        caller.addLabel("start");
        caller.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 6, 7, 0, 0, 0,
                new ImmutableMethodReference(PROXY, "compute", List.of("Ljava/lang/Object;", "I"), "I")));
        if (!protectResult) caller.addLabel("end");
        caller.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 2));
        if (protectResult) caller.addLabel("end");
        caller.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 3, 0, 2));
        caller.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 3));
        caller.addLabel("handler"); caller.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 5));
        caller.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 3, 0, 1));
        caller.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 3, 3, 2));
        caller.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 3, 3, 7));
        caller.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 3));
        caller.addCatch("Ljava/lang/RuntimeException;", caller.getLabel("start"), caller.getLabel("end"), caller.getLabel("handler"));
        var body = new MethodImplementationBuilder(3);
        body.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, EFFECTS));
        body.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, 1));
        body.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, EFFECTS));
        body.addInstruction(new BuilderInstruction21t(Opcode.IF_LTZ, 2, body.getLabel("throw")));
        body.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 1, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/String;", "length", List.of(), "I")));
        body.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        body.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 0, 0, 2));
        body.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        body.addLabel("throw");
        body.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 0, new ImmutableTypeReference("Ljava/lang/IllegalArgumentException;")));
        body.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/IllegalArgumentException;", "<init>", List.of(), "V")));
        body.addInstruction(new BuilderInstruction11x(Opcode.THROW, 0));
        List<ClassDef> classes = new ArrayList<>(input.getClasses());
        classes.add(new ImmutableClassDef(PROXY, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(
                method(PROXY, "compute", List.of("Ljava/lang/Object;", "I"), "I", PUBLIC_STATIC, proxy.getMethodImplementation()))));
        classes.add(new ImmutableClassDef(CALLER, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(
                method(CALLER, "compute", List.of("Ljava/lang/Object;", "I"), "I", PUBLIC_STATIC, caller.getMethodImplementation()))));
        classes.add(new ImmutableClassDef(TARGET, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(
                new ImmutableField(TARGET, "effects", "I", PUBLIC_STATIC, null, Set.of(), Set.of())), List.of(
                method(TARGET, "compute", List.of("Ljava/lang/String;", "I"), "I", PUBLIC_STATIC, body.getMethodImplementation()))));
        return new ImmutableDexFile(input.getOpcodes(), classes);
    }
    @Test public void protectedMemberExpansionPreservesHandlersAndCatchLiveRegisters() throws Exception {
        for (boolean protectResult : List.of(false, true)) {
            var result = clean(protectedMemberFixture(protectResult));
            Method output = new DexContext(result.dex()).findMethod(CALLER + "->compute(Ljava/lang/Object;I)I").orElseThrow();
            assertFalse(hasProxy(output)); assertTrue(output.getImplementation().getRegisterCount() > 8);
            var graph = new CodeGraph(output.getImplementation()); int throwing = 0;
            for (int at = 0; at < graph.size(); at++) {
                Instruction instruction = graph.at(at);
                if (instruction.getOpcode() == Opcode.CHECK_CAST || instruction instanceof ReferenceInstruction ref
                        && ref.getReference() instanceof MethodReference call && call.getDefiningClass().equals(TARGET)) {
                    assertEquals(List.of("Ljava/lang/RuntimeException;"), graph.protection(at).stream().map(CodeGraph.Handler::type).toList());
                    throwing++;
                }
            }
            assertEquals(2, throwing);
            Path path = Files.createTempFile("np-protected-members-", ".dex");
            try { Files.delete(path); DexFiles.write(path, result.dex()); assertEquals(0, clean(DexFiles.read(path)).changedMethods()); }
            finally { Files.deleteIfExists(path); }
        }
    }
    @Test public void changingGuardFieldInvalidatesTheProxyProof() {
        DexFile source = fixture("literal", false); DexContext dex = new DexContext(source);
        Method guardBody = dex.findMethod(Signatures.of(guard)).orElseThrow();
        FieldReference field = (FieldReference)((ReferenceInstruction)new CodeGraph(guardBody.getImplementation()).at(1)).getReference();
        var write = new MethodImplementationBuilder(1);
        // Zero is different from the fixture's negative/positive non-zero helper field.
        Fixtures.integer(write, 0, 0); write.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, field));
        write.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        List<ClassDef> classes = new ArrayList<>();
        for (ClassDef cls : source.getClasses()) {
            if (!cls.getType().equals(CALLER)) { classes.add(cls); continue; }
            List<Method> methods = new ArrayList<>(); cls.getMethods().forEach(methods::add);
            methods.add(method(CALLER, "changeGuard", List.of(), "V", PUBLIC_STATIC, write.getMethodImplementation()));
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
        }
        assertTrue(hasProxy(getCaller(clean(new ImmutableDexFile(source.getOpcodes(), classes)).dex(), false)));
    }
    @Test public void preservesWideParametersAcrossScratchGrowthAndDexRoundTrip() throws Exception {
        var result = clean(fixture("wide", false));
        Path file = Files.createTempFile("np-proxy-wide", ".dex");
        try {
            Files.delete(file);
            DexFiles.write(file, result.dex()); Method out = getCaller(DexFiles.read(file), true);
            assertFalse(hasProxy(out)); assertTrue(out.getImplementation().getRegisterCount() > 3);
            for (long n : new long[]{0, -1, Long.MIN_VALUE, Long.MAX_VALUE, 0x12345678abcdef01L}) assertEquals(n, executeWide(out, n));
        } finally { Files.deleteIfExists(file); }
    }
    private long executeWide(Method method, long input) {
        int size = method.getImplementation().getRegisterCount(); int[] words = new int[size];
        words[size - 2] = (int)input; words[size - 1] = (int)(input >>> 32); long pending = 0;
        for (Instruction i : method.getImplementation().getInstructions()) {
            Opcode op = i.getOpcode();
            if (op == Opcode.NOP) continue;
            if (op.name.startsWith("move-wide")) {
                var move = (TwoRegisterInstruction)i; int low = words[move.getRegisterB()], high = words[move.getRegisterB() + 1];
                words[move.getRegisterA()] = low; words[move.getRegisterA() + 1] = high;
            } else if (op.name.startsWith("invoke-static")) {
                assertEquals(TARGET + "->echo(J)J", Signatures.of((MethodReference)((ReferenceInstruction)i).getReference()));
                int[] args = ConstantEvaluator.arguments(i); assertEquals(2, args.length); assertEquals(args[0] + 1, args[1]);
                pending = Integer.toUnsignedLong(words[args[0]]) | ((long)words[args[1]] << 32);
            } else if (op == Opcode.MOVE_RESULT_WIDE) {
                int dest = ((OneRegisterInstruction)i).getRegisterA(); words[dest] = (int)pending; words[dest + 1] = (int)(pending >>> 32);
            } else if (op == Opcode.RETURN_WIDE) {
                int src = ((OneRegisterInstruction)i).getRegisterA(); return Integer.toUnsignedLong(words[src]) | ((long)words[src + 1] << 32);
            } else fail("Unexpected wide probe opcode: " + op);
        }
        throw new AssertionError("No return");
    }
    private DexFile highRegisters(String mode) {
        boolean invoke = mode.equals("invoke"), put = mode.equals("put"), crowded = mode.equals("crowded");
        List<String> params = invoke ? List.of("I", "J", "I") : put ? List.of(TARGET, "J") : List.of(TARGET);
        var field = new ImmutableFieldReference(TARGET, "wide", "J");
        var b = new MethodImplementationBuilder(invoke ? 6 : put ? 5 : 4);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, guard));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("fallback")));
        if (invoke) {
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 4, 5, 3, 4, 2, 0,
                    new ImmutableMethodReference(TARGET, "combine", params, "J")));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_WIDE, 0));
        } else if (put) b.addInstruction(new BuilderInstruction22c(Opcode.IPUT_WIDE, 3, 2, field));
        else b.addInstruction(new BuilderInstruction22c(Opcode.IGET_WIDE, 0, 3, field));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, put ? 3 : 0));
        b.addLabel("fallback"); b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 0, -1));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
        Method hidden = method(PROXY, "high", params, "J", PUBLIC_STATIC, b.getMethodImplementation());
        b = new MethodImplementationBuilder(340);
        for (int r = invoke || crowded ? 0 : 3; r < 16; r++) Fixtures.integer(b, r, 100 + r);
        int words = invoke ? 4 : put ? 3 : 1;
        b.addInstruction(new BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, 340 - words, words, hidden));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_WIDE, 30));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 32, invoke || crowded ? 0 : 3, 15));
        for (int r = invoke || crowded ? 1 : 4; r < 15; r++)
            b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 32, 32, r));
        // Keep every selected low register observable after the expanded member operation.
        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 32, EFFECTS));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 30));
        Method caller = method(CALLER, "high", params, "J", PUBLIC_STATIC, b.getMethodImplementation());
        b = new MethodImplementationBuilder(6);
        b.addInstruction(new BuilderInstruction23x(Opcode.SUB_INT, 0, 2, 5));
        b.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_LONG, 0, 0));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_LONG, 0, 0, 3));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
        Method combine = method(TARGET, "combine", List.of("I", "J", "I"), "J", PUBLIC_STATIC, b.getMethodImplementation());
        List<ClassDef> classes = new ArrayList<>(input.getClasses());
        classes.add(new ImmutableClassDef(PROXY, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(hidden)));
        classes.add(new ImmutableClassDef(CALLER, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(caller)));
        classes.add(new ImmutableClassDef(TARGET, 1, "Ljava/lang/Object;", List.of(), null, Set.of(),
                List.of(new ImmutableField(TARGET, "wide", "J", 1, null, Set.of(), Set.of()),
                        new ImmutableField(TARGET, "effects", "I", PUBLIC_STATIC, null, Set.of(), Set.of())), List.of(combine)));
        return new ImmutableDexFile(input.getOpcodes(), classes);
    }
    @Test public void restoresHighRegisterMembersAndPacksNoncontiguousWideArguments() throws Exception {
        for (String mode : List.of("invoke", "get", "put")) {
            var result = clean(highRegisters(mode));
            Method output = new DexContext(result.dex()).methods().values().stream()
                    .filter(m -> m.getDefiningClass().equals(CALLER) && m.getName().equals("high")).findFirst().orElseThrow();
            assertFalse(mode, hasProxy(output));
            if (mode.equals("invoke")) {
                assertTrue(output.getImplementation().getRegisterCount() > 340);
                for (Instruction i : output.getImplementation().getInstructions()) if (i.getOpcode() == Opcode.INVOKE_STATIC_RANGE) {
                    var range = (RegisterRangeInstruction) i;
                    assertEquals(4, range.getRegisterCount()); assertTrue(range.getStartRegister() >= 340);
                }
            } else {
                for (Instruction i : output.getImplementation().getInstructions()) if (i.getOpcode() == Opcode.IGET_WIDE || i.getOpcode() == Opcode.IPUT_WIDE) {
                    var access = (TwoRegisterInstruction) i;
                    assertTrue(access.getRegisterA() < 2); assertEquals(2, access.getRegisterB());
                }
            }
            Path file = Files.createTempFile("np-high-", ".dex");
            try {
                Files.delete(file); DexFiles.write(file, result.dex());
                assertEquals(mode, 0, clean(DexFiles.read(file)).changedMethods());
            } finally { Files.deleteIfExists(file); }
        }
    }
    @Test public void retainsFieldProxyWhenEveryLowTemporaryIsLive() {
        var result = clean(highRegisters("crowded"));
        Method output = new DexContext(result.dex()).methods().values().stream()
                .filter(m -> m.getDefiningClass().equals(CALLER) && m.getName().equals("high")).findFirst().orElseThrow();
        assertTrue(hasProxy(output));
        assertTrue(notes(result).stream().anyMatch(n -> n.contains("instruction encoding")));
    }

    private DexFile classProxyFixture(String mode) {
        String owner = mode.equals("business-owner") ? PROXY : guard.getDefiningClass();
        var proxy = new MethodImplementationBuilder(2);
        if (mode.equals("guarded")) {
            proxy.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, guard));
            proxy.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
            proxy.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, proxy.getLabel("fallback")));
        } else if (mode.equals("unknown-branch")) {
            proxy.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 1, proxy.getLabel("fallback")));
        }
        proxy.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 1, new ImmutableTypeReference("Ljava/lang/String;")));
        for (String name : List.of("first", "second")) {
            MethodReference target = mode.equals("cycle") && name.equals("second")
                    ? new ImmutableMethodReference(owner, "wrapped", List.of("Ljava/lang/Object;"), "Ljava/lang/String;")
                    : new ImmutableMethodReference(TARGET, name, List.of("Ljava/lang/String;"), "Ljava/lang/String;");
            proxy.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 1, 0, 0, 0, 0, target));
            proxy.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1));
        }
        proxy.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 1));
        if (mode.equals("guarded") || mode.equals("unknown-branch")) {
            proxy.addLabel("fallback"); Fixtures.string(proxy, 0, "fallback");
            proxy.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        }
        List<Method> extra = new ArrayList<>();
        extra.add(method(owner, "wrapped", List.of("Ljava/lang/Object;"), "Ljava/lang/String;",
                PUBLIC_STATIC | (mode.equals("synchronized") ? AccessFlags.DECLARED_SYNCHRONIZED.getValue() : 0), proxy.getMethodImplementation()));
        var literal = new MethodImplementationBuilder(1); Fixtures.string(literal, 0, "class-literal");
        literal.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        extra.add(method(owner, "literal", List.of(), "Ljava/lang/String;", PUBLIC_STATIC, literal.getMethodImplementation()));
        if (mode.equals("initializer") || mode.equals("initialized")) {
            var init = new MethodImplementationBuilder(1); Fixtures.integer(init, 0, 40);
            init.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, EFFECTS));
            init.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            extra.add(method(owner, "<clinit>", List.of(), "V", AccessFlags.STATIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(), init.getMethodImplementation()));
        }
        if (mode.equals("empty-initializer") || mode.equals("private-table") || mode.equals("table-business")) {
            var init = new MethodImplementationBuilder(3);
            if (!mode.equals("empty-initializer")) {
                Fixtures.integer(init, 0, 1);
                init.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 0, 0, new ImmutableTypeReference("[S")));
                Fixtures.integer(init, 1, 0); Fixtures.integer(init, 2, 7);
                init.addInstruction(new BuilderInstruction23x(Opcode.APUT_SHORT, 2, 0, 1));
                init.addInstruction(new BuilderInstruction21c(Opcode.SPUT_OBJECT, 0, new ImmutableFieldReference(owner, "table", "[S")));
            }
            if (mode.equals("table-business")) {
                Fixtures.integer(init, 0, 40); init.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, EFFECTS));
            }
            init.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            extra.add(method(owner, "<clinit>", List.of(), "V", AccessFlags.STATIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(), init.getMethodImplementation()));
        }
        if (mode.equals("instance-method")) {
            var instance = new MethodImplementationBuilder(1); instance.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            extra.add(method(owner, "business", List.of(), "V", AccessFlags.PUBLIC.getValue(), instance.getMethodImplementation()));
        }
        var classes = new ArrayList<ClassDef>();
        for (ClassDef cls : input.getClasses()) {
            if (!cls.getType().equals(owner)) { classes.add(cls); continue; }
            var methods = new ArrayList<Method>();
            for (Method m : cls.getMethods()) {
                if (mode.equals("missing-string-helper") && NpHelpers.descriptor(m).equals("(Ljava/lang/String;)Ljava/lang/String;")) continue;
                if (mode.equals("fake-hash") && NpHelpers.descriptor(m).equals("(Ljava/lang/Object;)I")) {
                    var fake = new MethodImplementationBuilder(2); Fixtures.integer(fake, 0, 0);
                    fake.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
                    methods.add(method(owner, m.getName(), List.of("Ljava/lang/Object;"), "I", PUBLIC_STATIC, fake.getMethodImplementation()));
                } else methods.add(m);
            }
            methods.addAll(extra); var fields = new ArrayList<Field>(); cls.getFields().forEach(fields::add);
            if (mode.equals("private-table") || mode.equals("table-business")) fields.add(new ImmutableField(owner, "table", "[S",
                    AccessFlags.PRIVATE.getValue() | AccessFlags.STATIC.getValue() | AccessFlags.FINAL.getValue(), null, Set.of(), Set.of()));
            if (mode.equals("business-field")) fields.add(new ImmutableField(owner, "business", "Ljava/lang/Object;", PUBLIC_STATIC, null, Set.of(), Set.of()));
            classes.add(new ImmutableClassDef(owner, cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(), fields, methods));
        }
        if (mode.equals("business-owner")) classes.add(new ImmutableClassDef(owner, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), extra));
        var call = new MethodImplementationBuilder(2);
        MethodReference wrapped = new ImmutableMethodReference(owner, "wrapped", List.of("Ljava/lang/Object;"), "Ljava/lang/String;");
        call.addLabel("start");
        call.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 1, 0, 0, 0, 0, wrapped));
        call.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        if (mode.equals("initialized")) {
            call.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 1, 0, 0, 0, 0, wrapped));
            call.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        }
        call.addLabel("end"); call.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        if (mode.equals("protected")) {
            call.addLabel("handler"); call.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
            Fixtures.string(call, 0, "caught"); call.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
            call.addCatch(call.getLabel("start"), call.getLabel("end"), call.getLabel("handler"));
        }
        var literalCall = new MethodImplementationBuilder(1);
        literalCall.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference(owner, "literal", List.of(), "Ljava/lang/String;")));
        literalCall.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        literalCall.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        classes.add(new ImmutableClassDef(CALLER, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(
                method(CALLER, "ordered", List.of("Ljava/lang/Object;"), "Ljava/lang/String;", PUBLIC_STATIC, call.getMethodImplementation()),
                method(CALLER, "literal", List.of(), "Ljava/lang/String;", PUBLIC_STATIC, literalCall.getMethodImplementation()))));
        var first = new MethodImplementationBuilder(2);
        first.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, EFFECTS));
        first.addInstruction(new BuilderInstruction22b(Opcode.MUL_INT_LIT8, 0, 0, 10));
        first.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, 1));
        first.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, EFFECTS));
        first.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 1));
        var second = new MethodImplementationBuilder(2);
        second.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, EFFECTS));
        second.addInstruction(new BuilderInstruction22b(Opcode.MUL_INT_LIT8, 0, 0, 10));
        second.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, 2));
        second.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, EFFECTS));
        second.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 1));
        classes.add(new ImmutableClassDef(TARGET, 1, "Ljava/lang/Object;", List.of(), null, Set.of(),
                List.of(new ImmutableField(TARGET, "effects", "I", PUBLIC_STATIC, null, Set.of(), Set.of())), List.of(
                method(TARGET, "first", List.of("Ljava/lang/String;"), "Ljava/lang/String;", PUBLIC_STATIC, first.getMethodImplementation()),
                method(TARGET, "second", List.of("Ljava/lang/String;"), "Ljava/lang/String;", PUBLIC_STATIC, second.getMethodImplementation()))));
        return new ImmutableDexFile(input.getOpcodes(), classes);
    }
    private Method ordered(DexFile dex) {
        return new DexContext(dex).methods().get(CALLER + "->ordered(Ljava/lang/Object;)Ljava/lang/String;");
    }
    private List<MethodReference> calls(Method method) {
        var refs = new ArrayList<MethodReference>();
        for (Instruction i : method.getImplementation().getInstructions())
            if (i.getOpcode().name.startsWith("invoke") && i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m) refs.add(m);
        return refs;
    }
    @Test public void proxyClassRestoresUnguardedAndMultiOperationMethodsInOrder() throws Exception {
        for (String mode : List.of("ordered", "guarded")) {
            var result = clean(classProxyFixture(mode)); Method output = ordered(result.dex());
            assertEquals(mode, List.of("first", "second"), calls(output).stream().map(MethodReference::getName).toList());
            var graph = new CodeGraph(output.getImplementation()); int cast = -1, invoke = -1;
            for (int i = 0; i < graph.size(); i++) {
                if (graph.at(i).getOpcode() == Opcode.CHECK_CAST && cast < 0) cast = i;
                if (graph.at(i).getOpcode().name.startsWith("invoke") && invoke < 0) invoke = i;
            }
            assertTrue(mode, cast >= 0 && cast < invoke);
            assertTrue(result.evidence().candidates().stream().anyMatch(c -> c.rule().equals("np.class-proxy.trace.v1") && c.method().contains("->wrapped(")));
            assertTrue(result.evidence().decisions().stream().anyMatch(d -> d.method().contains("->wrapped(")));
            Method literal = new DexContext(result.dex()).methods().get(CALLER + "->literal()Ljava/lang/String;");
            assertTrue(calls(literal).isEmpty()); assertEquals("class-literal", Fixtures.execute(literal, 0));
            Path file = Files.createTempFile("np-class-proxy-", ".dex");
            try {
                Files.delete(file); DexFiles.write(file, result.dex());
                assertEquals(mode, 0, clean(DexFiles.read(file)).changedMethods());
            } finally { Files.deleteIfExists(file); }
        }
    }
    @Test public void proxyClassKeepsUnknownBranchesCyclesAndSynchronization() {
        for (String mode : List.of("unknown-branch", "cycle", "synchronized"))
            assertTrue(mode, calls(ordered(clean(classProxyFixture(mode)).dex())).stream().anyMatch(m -> m.getName().equals("wrapped")));
    }
    @Test public void proxyClassRestoresProtectedCallsByDefault() {
        assertFalse(calls(ordered(clean(classProxyFixture("protected")).dex())).stream().anyMatch(m -> m.getName().equals("wrapped")));
    }
    @Test public void proxyClassPreservesFirstInitializationAndUsesOnlySuccessfulCalls() {
        for (String mode : List.of("initializer", "initialized", "table-business")) {
            var result = clean(classProxyFixture(mode)); var refs = calls(ordered(result.dex()));
            assertEquals(mode, 1, refs.stream().filter(m -> m.getName().equals("wrapped")).count());
            assertEquals(mode, mode.equals("initialized") ? List.of("wrapped", "first", "second") : List.of("wrapped"), refs.stream().map(MethodReference::getName).toList());
        }
    }
    @Test public void proxyClassRestoresFirstCallsWithProvenHarmlessInitialization() {
        for (String mode : List.of("empty-initializer", "private-table")) {
            var result = clean(classProxyFixture(mode));
            assertEquals(mode, List.of("first", "second"), calls(ordered(result.dex())).stream().map(MethodReference::getName).toList());
            assertTrue(mode, result.evidence().candidates().stream().anyMatch(c -> c.method().contains("->wrapped(")
                    && c.facts().stream().anyMatch(f -> f.startsWith("proxyInitialization=verified"))));
        }
    }
    @Test public void proxyClassNeedsVerifiedHelperSemanticsAndClassStructure() {
        for (String mode : List.of("business-owner", "fake-hash", "missing-string-helper", "business-field", "instance-method"))
            assertTrue(mode, calls(ordered(clean(classProxyFixture(mode)).dex())).stream().anyMatch(m -> m.getName().equals("wrapped")));
    }
    @Test public void newBatchConvergesAndIsIdempotentAfterSerialization() throws Exception {
        for (String name : List.of("hide-methods", "reflect", "encrypt-resource", "opt")) {
            DexFile source = DexFiles.read(Path.of(getClass().getResource("/np-batch3/" + name + ".dex").toURI()));
            var app = new Deobfuscator(TransformerRegistry.discover());
            var specs = RunConfiguration.defaults().transformers(); var r = app.transform(source, specs, 20);
            assertEquals(name, 0, r.failedMethods()); assertTrue(name, r.methods().stream().allMatch(DexEngine.MethodReport::converged));
            long proxies = r.methods().stream().flatMap(m -> m.steps().stream()).filter(s -> s.pass().equals("np.method-hiding")).mapToLong(s -> s.result().edits()).sum();
            if (name.equals("hide-methods")) assertTrue(proxies > 1000); else assertEquals(name, 0, proxies);
            Path file = Files.createTempFile("np-batch3-" + name, ".dex");
            try {
                Files.delete(file);
                DexFiles.write(file, r.dex()); var second = app.transform(DexFiles.read(file), specs, 20);
                assertEquals(name, 0, second.failedMethods()); assertEquals(name, 0, second.changedMethods()); assertEquals(name, 0, second.dexEdits());
            } finally { Files.deleteIfExists(file); }
        }
    }
}
