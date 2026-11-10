package me.naptila.deobfuscator;

import java.nio.file.*;
import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transformers.cleanup.UnreachableCodeTransformer;
import me.naptila.deobfuscator.transformers.np.NpCleanup;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.jf.dexlib2.immutable.value.ImmutableIntEncodedValue;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class ResidualCleanupTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    private static final String OWNER = "Lsample/Test;";
    private static final ImmutableFieldReference TRACE = new ImmutableFieldReference(OWNER, "trace", "I");
    private static final ImmutableMethodReference MARK = new ImmutableMethodReference(OWNER, "mark", List.of("I", "I"), "Z");
    private static List<ImmutableMethodParameter> parameters(int n) {
        List<ImmutableMethodParameter> p = new ArrayList<>(); for (int i = 0; i < n; i++) p.add(new ImmutableMethodParameter("I", Set.of(), "p" + i)); return p;
    }
    private Method marker() {
        var b = new MethodImplementationBuilder(4);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, TRACE));
        b.addInstruction(new BuilderInstruction22b(Opcode.MUL_INT_LIT8, 0, 0, 10));
        b.addInstruction(new BuilderInstruction12x(Opcode.ADD_INT_2ADDR, 0, 2));
        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, TRACE));
        b.addInstruction(new BuilderInstruction23x(Opcode.AND_INT, 0, 2, 3));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("zero")));
        Fixtures.integer(b, 0, 1);
        b.addLabel("zero"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        return Fixtures.method("mark", parameters(2), "Z", b.getMethodImplementation());
    }
    private void invoke(MethodImplementationBuilder b, int label) {
        Fixtures.integer(b, 2, label);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 2, 4, 0, 0, 0, MARK));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
    }
    private Method shortCircuit(boolean loop, boolean protectedCode, boolean allocation) {
        var b = new MethodImplementationBuilder(5);
        Fixtures.integer(b, 0, 0); b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, TRACE)); Fixtures.integer(b, 1, 0);
        b.addLabel("start"); invoke(b, 1);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("c")));
        invoke(b, 2); b.addInstruction(new BuilderInstruction21t(Opcode.IF_NEZ, 0, b.getLabel("yes")));
        b.addLabel("c");
        if (loop || allocation) Fixtures.integer(b, 2, 4);
        if (loop) Fixtures.go(b, "c");
        if (allocation) {
            b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 3, new ImmutableTypeReference("Ljava/lang/Object;")));
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 3, 0, 0, 0, 0,
                    new ImmutableMethodReference("Ljava/lang/Object;", "<init>", List.of(), "V")));
        }
        invoke(b, 4); b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("join")));
        b.addLabel("yes"); Fixtures.integer(b, 1, 1);
        b.addLabel("join"); b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, TRACE));
        b.addInstruction(new BuilderInstruction22b(Opcode.MUL_INT_LIT8, 0, 0, 10));
        b.addInstruction(new BuilderInstruction12x(Opcode.ADD_INT_2ADDR, 0, 1));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        if (protectedCode) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
            Fixtures.integer(b, 0, -1); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
            b.addCatch(b.getLabel("start"), b.getLabel("join"), b.getLabel("handler"));
        }
        return Fixtures.method("flow", parameters(1), "I", b.getMethodImplementation());
    }
    private DexFile dex(Method method) {
        var field = new ImmutableField(OWNER, "trace", "I", AccessFlags.STATIC.getValue(), new ImmutableIntEncodedValue(0), Set.of(), Set.of());
        return new ImmutableDexFile(Opcodes.forApi(28), List.of(new ImmutableClassDef(OWNER, AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(field), List.of(method, marker()))));
    }
    @Test public void splittingKeepsShortCircuitOrderAndExecutesEachEffectOnce() throws Exception {
        Method input = shortCircuit(false, false, false); var context = new MethodContext(input);
        assertEquals(1, SharedConditionalRegions.run(context)); assertEquals(1, SharedConditionalRegions.run(context));
        assertEquals(0, SharedConditionalRegions.run(context));
        Path file = directory.getRoot().toPath().resolve("flow.dex"); DexFiles.write(file, dex(context.finish()));
        var before = new NpNumericInterpreter(dex(input)); var after = new NpNumericInterpreter(DexFiles.read(file));
        for (int bits = 0; bits < 8; bits++) {
            boolean a = (bits & 1) != 0, b = (bits & 2) != 0, c = (bits & 4) != 0;
            int trace = a ? b ? 12 : 124 : 14;
            int expected = trace * 10 + ((a && b) || c ? 1 : 0);
            assertEquals(expected, before.run(Signatures.of(input), bits));
            assertEquals(expected, after.run(Signatures.of(input), bits));
        }
    }
    @Test public void protectedRegionsAreNotCloned() {
        assertEquals(0, SharedConditionalRegions.run(new MethodContext(shortCircuit(false, true, false))));
    }
    private Method protectedBooleanLiteral(boolean protectJoin) {
        var b = new MethodImplementationBuilder(5);
        Fixtures.integer(b, 0, 0); b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, TRACE));
        b.addLabel("try"); invoke(b, 1);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("false")));
        invoke(b, 2); b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("false")));
        Fixtures.integer(b, 1, 1); Fixtures.go(b, "join");
        b.addLabel("false"); Fixtures.integer(b, 1, 0); b.addLabel("join");
        if (!protectJoin) b.addLabel("end");
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, TRACE));
        if (protectJoin) b.addLabel("end");
        b.addInstruction(new BuilderInstruction22b(Opcode.MUL_INT_LIT8, 0, 0, 10));
        b.addInstruction(new BuilderInstruction12x(Opcode.ADD_INT_2ADDR, 0, 1));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
        Fixtures.integer(b, 0, -1); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addCatch("Ljava/lang/Exception;", b.getLabel("try"), b.getLabel("end"), b.getLabel("handler"));
        return Fixtures.method("booleanLiteral", parameters(1), "I", b.getMethodImplementation());
    }
    @Test public void protectedBooleanLiteralClonesOnlyConstantsAndPreservesEffectsAndHandlers() throws Exception {
        Method input = protectedBooleanLiteral(true); var context = new MethodContext(input);
        assertEquals(1, SharedConditionalRegions.run(context)); assertEquals(0, SharedConditionalRegions.run(context));
        var graph = context.graph(); int calls = 0;
        for (int i = 0; i < graph.size(); i++) if (graph.at(i).getOpcode() == Opcode.INVOKE_STATIC) {
            assertEquals(List.of("Ljava/lang/Exception;"), graph.protection(i).stream().map(CodeGraph.Handler::type).toList()); calls++;
        }
        assertEquals(2, calls);
        var before = new NpNumericInterpreter(dex(input)); var after = new NpNumericInterpreter(dex(context.finish()));
        for (int bits = 0; bits < 8; bits++) {
            int expected = ((bits & 1) == 0 ? 1 : 12) * 10 + ((bits & 3) == 3 ? 1 : 0);
            assertEquals(expected, before.run(Signatures.of(input), bits)); assertEquals(expected, after.run(Signatures.of(input), bits));
        }
        Path path = directory.getRoot().toPath().resolve("protected-boolean.dex"); DexFiles.write(path, dex(context.finish()));
        assertEquals(0, SharedConditionalRegions.run(new MethodContext(new DexContext(DexFiles.read(path)).findMethod(Signatures.of(input)).orElseThrow())));
        assertEquals(0, SharedConditionalRegions.run(new MethodContext(protectedBooleanLiteral(false))));
    }
    @Test public void unreachableAlignmentNopDoesNotBlockSplitting() {
        Method input = shortCircuit(false, false, false); var context = new MethodContext(input);
        context.code().addInstruction(new BuilderInstruction10x(Opcode.NOP));
        assertEquals(1, SharedConditionalRegions.run(context));
        var before = new NpNumericInterpreter(dex(input)); var after = new NpNumericInterpreter(dex(context.finish()));
        for (int bits = 0; bits < 8; bits++) assertEquals(before.run(Signatures.of(input), bits), after.run(Signatures.of(input), bits));
    }
    @Test public void unreachableNopDoesNotMakeAUniqueConditionalRegionShared() throws Exception {
        var b = new MethodImplementationBuilder(5);
        Fixtures.integer(b, 0, 0); b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, TRACE));
        invoke(b, 1);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("no")));
        Fixtures.integer(b, 1, 9);
        b.addLabel("join");
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, TRACE));
        b.addInstruction(new BuilderInstruction22b(Opcode.MUL_INT_LIT8, 0, 0, 10));
        b.addInstruction(new BuilderInstruction12x(Opcode.ADD_INT_2ADDR, 0, 1));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addInstruction(new BuilderInstruction10x(Opcode.NOP));
        b.addLabel("no"); Fixtures.integer(b, 1, 7); Fixtures.go(b, "join");
        Method original = Fixtures.method("flow", parameters(1), "I", b.getMethodImplementation());
        var context = new MethodContext(original);
        for (int round = 0; round < 3; round++) {
            assertEquals(0, SharedConditionalRegions.run(context));
            assertEquals(0, new UnreachableCodeTransformer().run(context).edits());
        }
        Path file = directory.getRoot().toPath().resolve("unique-region.dex"); DexFiles.write(file, dex(context.finish()));
        Method reloaded = new DexContext(DexFiles.read(file)).findMethod(Signatures.of(original)).orElseThrow();
        assertEquals(0, SharedConditionalRegions.run(new MethodContext(reloaded)));
        for (int bits = 0; bits < 8; bits++) {
            int expected = 10 + ((bits & 1) == 0 ? 7 : 9);
            assertEquals(expected, new NpNumericInterpreter(dex(original)).run(Signatures.of(original), bits));
            assertEquals(expected, new NpNumericInterpreter(dex(reloaded)).run(Signatures.of(reloaded), bits));
        }
    }
    @Test public void plainShortCircuitLayoutsAreNormalizedWhenNpHelpersArePresent() throws Exception {
        Method original = shortCircuit(false, false, false);
        DexFile helpers = DexFiles.read(Path.of(getClass().getResource("/np-batch3/opt.dex").toURI()));
        List<ClassDef> classes = new ArrayList<>(helpers.getClasses()); classes.addAll(dex(original).getClasses());
        DexFile input = new ImmutableDexFile(helpers.getOpcodes(), classes);
        var pass = new NpCleanup();
        var result = new DexEngine(List.of(new UnreachableCodeTransformer(), pass), 20).transform(input);
        assertEquals(0, result.failedMethods()); assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged));
        var report = result.methods().stream().filter(m -> m.method().equals(Signatures.of(original))).findFirst().orElseThrow();
        assertTrue(report.edits() > 0);
        Method output = new DexContext(result.dex()).findMethod(Signatures.of(original)).orElseThrow();
        for (int bits = 0; bits < 8; bits++)
            assertEquals(new NpNumericInterpreter(input).run(Signatures.of(original), bits),
                    new NpNumericInterpreter(result.dex()).run(Signatures.of(output), bits));
        Path file = directory.getRoot().toPath().resolve("plain-np-layout.dex"); DexFiles.write(file, result.dex());
        assertEquals(0, new DexEngine(List.of(new UnreachableCodeTransformer(), pass), 20).transform(DexFiles.read(file)).changedMethods());
    }
    @Test public void plainLayoutsWithoutNpHelpersAreRetained() {
        Method original = shortCircuit(false, false, false);
        var result = new DexEngine(List.of(new NpCleanup()), 20).transform(dex(original));
        assertEquals(0, result.changedMethods());
    }
    private Method switchDefaultRelay(boolean bothDefault) {
        var b = new MethodImplementationBuilder(5);
        Fixtures.integer(b, 0, 0); b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, TRACE));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 1, 4));
        b.addInstruction(new BuilderInstruction31t(Opcode.PACKED_SWITCH, 4, b.getLabel("firstPayload")));
        Fixtures.go(b, "default");
        b.addLabel("case"); Fixtures.integer(b, 2, 4);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 2, 1, 0, 0, 0, MARK));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        invoke(b, 1); b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("relay")));
        if (bothDefault) Fixtures.go(b, "default"); else Fixtures.integer(b, 1, 1);
        Fixtures.go(b, "join");
        b.addLabel("relay"); Fixtures.go(b, "default");
        b.addLabel("default"); Fixtures.integer(b, 1, -1);
        b.addLabel("join");
        b.addInstruction(new BuilderInstruction31t(Opcode.PACKED_SWITCH, 1, b.getLabel("secondPayload")));
        Fixtures.integer(b, 1, 7); Fixtures.go(b, "result");
        b.addLabel("found"); Fixtures.integer(b, 1, 9);
        b.addLabel("result"); b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, TRACE));
        b.addInstruction(new BuilderInstruction22b(Opcode.MUL_INT_LIT8, 0, 0, 10));
        b.addInstruction(new BuilderInstruction12x(Opcode.ADD_INT_2ADDR, 0, 1));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("firstPayload");
        b.addInstruction(new BuilderPackedSwitchPayload(0, Collections.nCopies(8, b.getLabel("case"))));
        b.addLabel("secondPayload"); b.addInstruction(new BuilderPackedSwitchPayload(1, List.of(b.getLabel("found"))));
        return Fixtures.method("flow", parameters(1), "I", b.getMethodImplementation());
    }
    @Test public void switchDefaultRelaysKeepLiveDiscriminatorsAndSideEffects() throws Exception {
        Method original = switchDefaultRelay(false);
        var context = new MethodContext(original);
        assertEquals(0, SwitchDefaults.run(context));
        assertEquals(1, SwitchDefaultEdges.run(context)); assertEquals(0, SwitchDefaultEdges.run(context));
        Path file = directory.getRoot().toPath().resolve("switch-relay.dex"); DexFiles.write(file, dex(context.finish()));
        var before = new NpNumericInterpreter(dex(original)); var after = new NpNumericInterpreter(DexFiles.read(file));
        for (int bits : new int[]{Integer.MIN_VALUE, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 16, Integer.MAX_VALUE}) {
            int expected = bits >= 0 && bits < 8 ? 410 + ((bits & 1) == 0 ? 7 : 9) : 7;
            assertEquals(expected, before.run(Signatures.of(original), bits));
            assertEquals(expected, after.run(Signatures.of(original), bits));
        }
    }
    @Test public void identicalSwitchDefaultArmsAreNotRepeatedlySplit() {
        Method original = switchDefaultRelay(true); var context = new MethodContext(original);
        for (int round = 0; round < 3; round++) assertEquals(0, SwitchDefaultEdges.run(context));
        var after = new NpNumericInterpreter(dex(context.finish()));
        for (int bits = 0; bits < 9; bits++) assertEquals(bits < 8 ? 417 : 7, after.run(Signatures.of(original), bits));
    }
    @Test public void unrelatedPlainReturnEdgesAreRetainedEvenWithNpHelpersPresent() throws Exception {
        var b = new MethodImplementationBuilder(1);
        Fixtures.integer(b, 0, 7); Fixtures.go(b, "done");
        b.addLabel("done"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        Method original = Fixtures.method("plainReturn", List.of(), "I", b.getMethodImplementation());
        DexFile helpers = DexFiles.read(Path.of(getClass().getResource("/np-batch3/opt.dex").toURI()));
        List<ClassDef> classes = new ArrayList<>(helpers.getClasses()); classes.addAll(dex(original).getClasses());
        DexFile input = new ImmutableDexFile(helpers.getOpcodes(), classes);
        var result = new DexEngine(List.of(new NpCleanup()), 20).transform(input);
        var report = result.methods().stream().filter(m -> m.method().equals(Signatures.of(original))).findFirst().orElseThrow();
        assertEquals(0, report.edits());
        Method output = new DexContext(result.dex()).findMethod(Signatures.of(original)).orElseThrow();
        assertEquals(MethodFingerprint.of(new DexContext(input), original), MethodFingerprint.of(new DexContext(result.dex()), output));
    }
    @Test public void sharedMoveAssignmentKeepsShortCircuitOrder() {
        var source = new MethodContext(shortCircuit(false, false, false));
        CodeGraph graph = source.graph();
        for (int i = 0; i < graph.size(); i++) if (graph.at(i) instanceof org.jf.dexlib2.iface.instruction.NarrowLiteralInstruction literal
                && literal.getNarrowLiteral() == 1 && ((org.jf.dexlib2.iface.instruction.OneRegisterInstruction)graph.at(i)).getRegisterA() == 1)
            source.code().replaceInstruction(i, new BuilderInstruction12x(Opcode.MOVE, 1, 3));
        source.code().addInstruction(0, new BuilderInstruction31i(Opcode.CONST, 3, 1));
        Method input = source.finish(); var context = new MethodContext(input);
        assertEquals(1, SharedConditionalRegions.run(context)); assertEquals(1, SharedConditionalRegions.run(context));
        assertEquals(0, SharedConditionalRegions.run(context));
        var before = new NpNumericInterpreter(dex(input)); var after = new NpNumericInterpreter(dex(context.finish()));
        for (int bits = 0; bits < 8; bits++) assertEquals(before.run(Signatures.of(input), bits), after.run(Signatures.of(input), bits));
    }
    @Test public void backwardSharedEdgesKeepEveryShortCircuitEffect() throws Exception {
        var b = new MethodImplementationBuilder(5);
        Fixtures.integer(b, 0, 0); b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, TRACE));
        Fixtures.integer(b, 1, 0); Fixtures.go(b, "a");
        b.addLabel("c"); invoke(b, 4);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("join")));
        b.addLabel("yes"); Fixtures.integer(b, 1, 1); Fixtures.go(b, "join");
        b.addLabel("a"); invoke(b, 1);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("c")));
        invoke(b, 2); b.addInstruction(new BuilderInstruction21t(Opcode.IF_NEZ, 0, b.getLabel("yes")));
        Fixtures.go(b, "c");
        b.addLabel("join"); b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, TRACE));
        b.addInstruction(new BuilderInstruction22b(Opcode.MUL_INT_LIT8, 0, 0, 10));
        b.addInstruction(new BuilderInstruction12x(Opcode.ADD_INT_2ADDR, 0, 1));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        Method input = Fixtures.method("flow", parameters(1), "I", b.getMethodImplementation());
        var context = new MethodContext(input); assertEquals(1, SharedConditionalRegions.run(context));
        for (int i = 0; i < 8 && SharedConditionalRegions.run(context) != 0; i++) assertTrue(i < 7);
        Path file = directory.getRoot().toPath().resolve("backward.dex"); DexFiles.write(file, dex(context.finish()));
        var before = new NpNumericInterpreter(dex(input)); var after = new NpNumericInterpreter(DexFiles.read(file));
        for (int bits = 0; bits < 8; bits++) {
            boolean a = (bits & 1) != 0, c = (bits & 4) != 0;
            int trace = a ? (bits & 2) != 0 ? 12 : 124 : 14;
            int expected = trace * 10 + ((a && (bits & 2) != 0) || c ? 1 : 0);
            assertEquals(expected, before.run(Signatures.of(input), bits));
            assertEquals(expected, after.run(Signatures.of(input), bits));
        }
    }
    @Test public void cyclicAndAllocationRegionsAreNotCloned() {
        for (Method input : List.of(shortCircuit(true, false, false), shortCircuit(false, false, true))) {
            var context = new MethodContext(input);
            SharedConditionalRegions.run(context); // May split the separate constant-only true edge.
            CodeGraph graph = context.graph(); int calls = 0;
            for (int i = 0; i < graph.size(); i++) if (graph.at(i).getOpcode() == Opcode.INVOKE_STATIC) calls++;
            assertEquals(3, calls);
        }
    }
    private Method lateReferenceChecks(int padding) {
        var b = new MethodImplementationBuilder(10);
        for (int i = 0; i < padding; i++) b.addInstruction(new BuilderInstruction10x(Opcode.NOP));
        Fixtures.integer(b, 0, 0); b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, TRACE));
        Fixtures.string(b, 3, "source"); Fixtures.string(b, 4, "dest");
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 0, 8));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 1, 9)); Fixtures.go(b, "guard");
        b.addLabel("shared"); b.addInstruction(new BuilderInstruction21t(Opcode.IF_NEZ, 0, b.getLabel("useA")));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 2, 3)); Fixtures.go(b, "checkB");
        b.addLabel("useA"); b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 2, 0));
        b.addLabel("checkB"); b.addInstruction(new BuilderInstruction21t(Opcode.IF_NEZ, 1, b.getLabel("useB")));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 5, 4)); Fixtures.go(b, "business");
        b.addLabel("useB"); b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 5, 1)); Fixtures.go(b, "business");
        b.addLabel("guard"); b.addInstruction(new BuilderInstruction21t(Opcode.IF_NEZ, 0, b.getLabel("shared")));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 1, b.getLabel("failed"))); Fixtures.go(b, "shared");
        b.addLabel("failed"); Fixtures.integer(b, 0, -1); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("business"); b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, TRACE));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, 1)); b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, TRACE));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 2, 0, 0, 0, 0, Fixtures.HASH));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 6));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 5, 0, 0, 0, 0, Fixtures.HASH));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 7));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 6, 6, 7));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 6, 6, 0)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 6));
        return Fixtures.method("lateReferences", List.of(new ImmutableMethodParameter("Ljava/lang/String;", Set.of(), "a"),
                new ImmutableMethodParameter("Ljava/lang/String;", Set.of(), "b")), "I", b.getMethodImplementation());
    }
    @Test public void lateConditionalEdgesPreserveReferenceAssignmentsAndBusinessEffects() throws Exception {
        for (int padding : new int[]{0, 540}) {
            Method input = lateReferenceChecks(padding); var context = new MethodContext(input);
            assertEquals(1, SharedConditionalRegions.run(context));
            assertEquals(0, SharedConditionalRegions.run(context));
            assertTrue(BranchThreading.run(context) > 0);
            for (int round = 0; round < 4; round++) {
                new UnreachableCodeTransformer().run(context);
                if (BranchThreading.run(context) == 0) break;
                assertTrue("conditional relocation must converge", round < 3);
            }
            assertEquals(0, BranchThreading.run(context));
            Path file = directory.getRoot().toPath().resolve("late-references-" + padding + ".dex"); DexFiles.write(file, dex(context.finish()));
            var before = new NpNumericInterpreter(dex(input)); var after = new NpNumericInterpreter(DexFiles.read(file));
            for (String a : new String[]{null, "", "A", "中文"}) for (String value : new String[]{null, "", "B", "😀"}) {
                int expected = a == null && value == null ? -1 : (a != null ? a : "source").hashCode() + (value != null ? value : "dest").hashCode() + 1;
                assertEquals(expected, before.run(Signatures.of(input), a, value)); assertEquals(expected, after.run(Signatures.of(input), a, value));
            }
            assertEquals(0, BranchThreading.run(new MethodContext(new DexContext(DexFiles.read(file)).methods().get(Signatures.of(input)))));
        }
    }
    @Test public void oppositeNullTestsUseTheTakenEdgesActualCondition() throws Exception {
        var source = new MethodContext(lateReferenceChecks(540)); CodeGraph graph = source.graph(); int changed = 0;
        for (int i = 0; i < graph.size(); i++) if (graph.at(i).getOpcode() == Opcode.IF_NEZ
                && ((org.jf.dexlib2.iface.instruction.OneRegisterInstruction) graph.at(i)).getRegisterA() == 0
                && graph.successors(i).get(0) < i) {
            source.code().replaceInstruction(i, new BuilderInstruction21t(Opcode.IF_EQZ, 0,
                    source.code().newLabelForIndex(graph.successors(i).get(0)))); changed++;
        }
        assertEquals(1, changed); Method input = source.finish(); var context = new MethodContext(input);
        assertEquals(1, SharedConditionalRegions.run(context)); assertEquals(0, SharedConditionalRegions.run(context));
        Path file = directory.getRoot().toPath().resolve("opposite-null-tests.dex"); DexFiles.write(file, dex(context.finish()));
        for (String a : new String[]{null, "", "A", "中文"}) for (String b : new String[]{null, "", "B", "😀"}) {
            int expected = a != null && b == null ? -1 : (a != null ? a : "source").hashCode() + (b != null ? b : "dest").hashCode() + 1;
            assertEquals(expected, new NpNumericInterpreter(dex(input)).run(Signatures.of(input), a, b));
            assertEquals(expected, new NpNumericInterpreter(DexFiles.read(file)).run(Signatures.of(input), a, b));
        }
    }
    @Test public void sharedNullPrefixesThatOverwriteTheTestedRegisterAreRetained() {
        var context = new MethodContext(lateReferenceChecks(0)); CodeGraph graph = context.graph();
        for (int i = 0; i < graph.size(); i++) if (graph.at(i).getOpcode() == Opcode.IF_NEZ
                && ((org.jf.dexlib2.iface.instruction.OneRegisterInstruction) graph.at(i)).getRegisterA() == 0
                && graph.successors(i).get(0) > i) {
            context.code().addInstruction(i + 1, new BuilderInstruction12x(Opcode.MOVE_OBJECT, 0, 3)); break;
        }
        assertEquals(0, SharedConditionalRegions.run(context));
    }
    private Method lateNumericComparison(boolean shared, boolean protectedTarget) {
        var b = new MethodImplementationBuilder(5);
        Fixtures.integer(b, 0, 0); b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, TRACE));
        Fixtures.integer(b, 3, 0);
        if (shared) b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 4, b.getLabel("late")));
        Fixtures.go(b, "late");
        b.addLabel("positive"); invoke(b, 2);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, TRACE));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, 7));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("negative"); invoke(b, 1);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, TRACE));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, -7));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("late"); b.addInstruction(new BuilderInstruction22t(Opcode.IF_LT, 4, 3, b.getLabel("negative")));
        b.addLabel("end"); Fixtures.go(b, "positive");
        if (protectedTarget) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 2));
            Fixtures.integer(b, 0, -99); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
            b.addCatch(b.getLabel("late"), b.getLabel("end"), b.getLabel("handler"));
        }
        return Fixtures.method("lateNumbers", parameters(1), "I", b.getMethodImplementation());
    }
    @Test public void lateTwoRegisterComparisonsKeepBothBusinessBranches() throws Exception {
        Method input = lateNumericComparison(false, false); var context = new MethodContext(input);
        assertTrue(BranchThreading.run(context) > 0);
        for (int round = 0; round < 4; round++) {
            new UnreachableCodeTransformer().run(context);
            if (BranchThreading.run(context) == 0) break;
            assertTrue("conditional relocation must converge", round < 3);
        }
        assertEquals(0, BranchThreading.run(context));
        Path file = directory.getRoot().toPath().resolve("late-numbers.dex"); DexFiles.write(file, dex(context.finish()));
        for (int n : new int[]{Integer.MIN_VALUE, -1, 0, 1, Integer.MAX_VALUE}) {
            int expected = n < 0 ? -6 : 9;
            assertEquals(expected, new NpNumericInterpreter(dex(input)).run(Signatures.of(input), n));
            assertEquals(expected, new NpNumericInterpreter(DexFiles.read(file)).run(Signatures.of(input), n));
        }
    }
    @Test public void sharedTestsAndDifferentExceptionCoverageAreNotRelocated() {
        assertEquals(0, BranchThreading.run(new MethodContext(lateNumericComparison(true, false))));
        assertEquals(0, BranchThreading.run(new MethodContext(lateNumericComparison(false, true))));
    }
    private Method terminalCalls(boolean allocation, boolean protectedCode, boolean cycle) {
        var b = new MethodImplementationBuilder(8);
        Fixtures.integer(b, 0, 0); b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, TRACE));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 4, 7)); Fixtures.integer(b, 1, 0);
        b.addInstruction(new BuilderInstruction22t(Opcode.IF_LE, 7, 1, b.getLabel("tail")));
        invoke(b, 1); b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("tail")));
        Fixtures.integer(b, 0, 123); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("tail");
        if (cycle) Fixtures.go(b, "tail");
        if (allocation) {
            b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 3, new ImmutableTypeReference("Lsample/Counted;")));
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 3, 0, 0, 0, 0,
                    new ImmutableMethodReference("Lsample/Counted;", "<init>", List.of(), "V")));
        }
        invoke(b, 4);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ, 7, b.getLabel("early")));
        invoke(b, 2); b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, TRACE));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("early"); b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, TRACE));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0)); b.addLabel("end");
        if (protectedCode) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
            Fixtures.integer(b, 0, -77); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
            b.addCatch(b.getLabel("tail"), b.getLabel("end"), b.getLabel("handler"));
        }
        return Fixtures.method("terminalCalls", parameters(1), "I", b.getMethodImplementation());
    }
    private DexFile terminalDex(Method method, boolean allocation) {
        DexFile base = dex(method); if (!allocation) return base;
        var b = new MethodImplementationBuilder(2);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 1, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/Object;", "<init>", List.of(), "V")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("LRootFlowFixtureProbe;", "construct", List.of(), "V")));
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, TRACE));
        b.addInstruction(new BuilderInstruction22b(Opcode.MUL_INT_LIT8, 0, 0, 10));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, 3));
        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, TRACE)); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        Method constructor = new ImmutableMethod("Lsample/Counted;", "<init>", List.of(), "V",
                AccessFlags.PUBLIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(), Set.of(), Set.of(), b.getMethodImplementation());
        var classes = new ArrayList<ClassDef>(base.getClasses());
        classes.add(new ImmutableClassDef("Lsample/Counted;", AccessFlags.PUBLIC.getValue(), "Ljava/lang/Object;", List.of(), null,
                Set.of(), List.of(), List.of(constructor)));
        return new ImmutableDexFile(base.getOpcodes(), classes);
    }
    @Test public void terminalTailSpecializationKeepsEveryExecutedBusinessCall() throws Exception {
        Method input = terminalCalls(false, false, false); var context = new MethodContext(input);
        assertEquals(0, SharedConditionalRegions.run(context));
        assertEquals(1, SharedConditionalRegions.run(context, true)); assertEquals(0, SharedConditionalRegions.run(context, true));
        Path file = directory.getRoot().toPath().resolve("terminal-calls.dex"); DexFiles.write(file, terminalDex(context.finish(), false));
        for (int n : new int[]{Integer.MIN_VALUE, -1, 0, 1, 2, 3, 4, Integer.MAX_VALUE}) {
            int expected = n <= 0 ? 4 : (n & 1) == 0 ? 142 : 123;
            assertEquals(expected, new NpNumericInterpreter(terminalDex(input, false)).run(Signatures.of(input), n));
            assertEquals(expected, new NpNumericInterpreter(DexFiles.read(file)).run(Signatures.of(input), n));
        }
        Method output = new DexContext(DexFiles.read(file)).methods().get(Signatures.of(input));
        assertEquals(0, SharedConditionalRegions.run(new MethodContext(output), true));
    }
    @Test public void terminalAllocationPathsStayClosedAndSerializable() throws Exception {
        Method input = terminalCalls(true, false, false); var context = new MethodContext(input);
        assertEquals(1, SharedConditionalRegions.run(context, true)); assertEquals(0, SharedConditionalRegions.run(context, true));
        Path file = directory.getRoot().toPath().resolve("terminal-allocations.dex"); DexFiles.write(file, terminalDex(context.finish(), true));
        Method output = new DexContext(DexFiles.read(file)).methods().get(Signatures.of(input));
        int allocations = 0, constructors = 0;
        for (var instruction : output.getImplementation().getInstructions()) {
            if (instruction.getOpcode() == Opcode.NEW_INSTANCE) allocations++;
            if (instruction.getOpcode() == Opcode.INVOKE_DIRECT) constructors++;
        }
        assertEquals(2, allocations); assertEquals(allocations, constructors);
        assertEquals(0, SharedConditionalRegions.run(new MethodContext(output), true));
    }
    @Test public void terminalCyclesAndProtectedOperationsAreRetained() {
        assertEquals(0, SharedConditionalRegions.run(new MethodContext(terminalCalls(false, false, true)), true));
        assertEquals(0, SharedConditionalRegions.run(new MethodContext(terminalCalls(true, true, false)), true));
    }
    private Method handler(boolean sharedBody) {
        var b = new MethodImplementationBuilder(3);
        if (sharedBody) { Fixtures.integer(b, 0, 0); Fixtures.go(b, "body"); }
        Fixtures.integer(b, 0, 42); Fixtures.integer(b, 1, 0);
        b.addLabel("start"); b.addInstruction(new BuilderInstruction23x(Opcode.DIV_INT, 0, 0, 1));
        b.addLabel("end"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("stub"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 2)); Fixtures.go(b, "body");
        b.addLabel("typed"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 2));
        Fixtures.integer(b, 0, 7); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("body"); b.addInstruction(new BuilderInstruction11x(Opcode.THROW, 2));
        b.addCatch("Ljava/lang/ArithmeticException;", b.getLabel("start"), b.getLabel("end"), b.getLabel("typed"));
        b.addCatch(b.getLabel("start"), b.getLabel("end"), b.getLabel("stub"));
        return Fixtures.method("handler", List.of(), "I", b.getMethodImplementation());
    }
    @Test public void handlerReconnectionKeepsOrderedCatchAndThrowDestination() throws Exception {
        var context = new MethodContext(handler(false)); assertEquals(1, HandlerEntries.run(context));
        new UnreachableCodeTransformer().run(context); assertEquals(0, HandlerEntries.run(context));
        Path file = directory.getRoot().toPath().resolve("handler.dex"); DexFiles.write(file, Fixtures.dex(context.finish()));
        Method output = Fixtures.first(DexFiles.read(file)); CodeGraph graph = new CodeGraph(output.getImplementation());
        var handlers = output.getImplementation().getTryBlocks().get(0).getExceptionHandlers();
        assertEquals(Arrays.asList("Ljava/lang/ArithmeticException;", null), handlers.stream().map(ExceptionHandler::getExceptionType).toList());
        int all = graph.index(handlers.get(1).getHandlerCodeAddress());
        assertEquals(Opcode.MOVE_EXCEPTION, graph.at(all).getOpcode()); assertEquals(Opcode.THROW, graph.at(all + 1).getOpcode());
    }
    @Test public void handlerBodyWithNormalEntryIsNotMoved() {
        assertEquals(0, HandlerEntries.run(new MethodContext(handler(true))));
    }
    /** Export deterministic effect/handler fixtures for optional ART verification. */
    public static void main(String[] args) throws Exception {
        Path root = Path.of(args[0]); Files.createDirectories(root);
        ResidualCleanupTest factory = new ResidualCleanupTest();
        Method flow = factory.shortCircuit(false, false, false), arithmetic = factory.handler(false);
        MethodContext parsing = new MethodContext(arithmetic);
        parsing.code().replaceInstruction(0, new BuilderInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("not-a-number")));
        parsing.code().replaceInstruction(2, new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/Integer;", "parseInt", List.of("Ljava/lang/String;"), "I")));
        parsing.code().addInstruction(3, new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        Method parsed = parsing.finish();
        parsed = new ImmutableMethod(OWNER, "parseHandler", List.of(), "I", parsed.getAccessFlags(), Set.of(), Set.of(), parsed.getImplementation());
        ClassDef base = factory.dex(flow).getClasses().iterator().next();
        List<Method> original = List.of(flow, factory.marker(), arithmetic, parsed), cleaned = new ArrayList<>();
        for (Method method : original) {
            MethodContext context = new MethodContext(method);
            for (int round = 0; round < 8; round++) {
                int edits = HandlerEntries.run(context) + SharedConditionalRegions.run(context)
                        + new UnreachableCodeTransformer().run(context).edits();
                if (edits == 0) break;
                if (round == 7) throw new AssertionError("Did not converge");
            }
            cleaned.add(context.finish());
        }
        for (boolean output : List.of(false, true)) {
            ClassDef cls = new ImmutableClassDef(OWNER, base.getAccessFlags(), base.getSuperclass(), List.of(), null,
                    Set.of(), base.getFields(), output ? cleaned : original);
            DexFiles.write(root.resolve(output ? "cleaned.dex" : "input.dex"), new ImmutableDexFile(Opcodes.forApi(28), List.of(cls)));
        }
    }

}
