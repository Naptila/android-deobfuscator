package me.naptila.deobfuscator;

import java.nio.file.*;
import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transformers.np.analysis.NpAnalysis;
import me.naptila.deobfuscator.transformers.np.instructions.InstructionTransformer;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.junit.*;
import static org.junit.Assert.*;

public class InstructionResidualTest {
    private static ClassDef helper;
    @BeforeClass public static void helper() throws Exception {
        var input = DexFiles.read(Path.of(InstructionResidualTest.class.getResource("/np-v2/opt.dex").toURI()));
        var context = new DexContext(input);
        var owners = NpAnalysis.of(context).model().helpers().owners();
        helper = context.classes().get(owners.iterator().next());
    }
    private static ImmutableMethodParameter param(String type) { return new ImmutableMethodParameter(type, Set.of(), null); }
    private static DexFile dex(Method method) {
        var classes = new ArrayList<ClassDef>(Fixtures.dex(method).getClasses()); classes.add(helper);
        return new ImmutableDexFile(Opcodes.forApi(28), classes);
    }
    private static Method rewrite(Method method) {
        var result = new DexEngine(List.of(new InstructionTransformer()), 10).transform(dex(method));
        assertEquals(0, result.failedMethods());
        assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged));
        return new DexContext(result.dex()).findMethod(Signatures.of(method)).orElseThrow();
    }
    private static long count(Method method, Opcode opcode) {
        long count = 0; for (Instruction i : method.getImplementation().getInstructions()) if (i.getOpcode() == opcode) count++; return count;
    }
    @Test public void twoInstructionNegationPairsKeepByteTruncationAndOverflow() {
        var b = new MethodImplementationBuilder(4);
        b.addInstruction(new BuilderInstruction22b(Opcode.RSUB_INT_LIT8, 0, 3, 0));
        b.addInstruction(new BuilderInstruction23x(Opcode.SUB_INT, 0, 2, 0));
        b.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_BYTE, 0, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        Method original = Fixtures.method("byteSum", List.of(param("I"), param("I")), "I", b.getMethodImplementation());
        Method restored = rewrite(original);
        assertEquals(0, count(restored, Opcode.SUB_INT)); assertEquals(1, count(restored, Opcode.INT_TO_BYTE));
        var run = new NpNumericInterpreter(dex(restored));
        for (int x : new int[]{Integer.MIN_VALUE, Integer.MAX_VALUE, -129, -128, -1, 0, 127, 128})
            for (int y : new int[]{Integer.MIN_VALUE, Integer.MAX_VALUE, -128, -1, 0, 1, 127})
                assertEquals((int)(byte)(x + y), run.run(Signatures.of(restored), x, y));
    }
    @Test public void twoInstructionWideNegationPreservesWraparound() {
        var b = new MethodImplementationBuilder(6);
        b.addInstruction(new BuilderInstruction12x(Opcode.NEG_LONG, 0, 4));
        b.addInstruction(new BuilderInstruction23x(Opcode.SUB_LONG, 0, 2, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
        Method original = Fixtures.method("wideSum", List.of(param("J"), param("J")), "J", b.getMethodImplementation());
        Method restored = rewrite(original); assertEquals(0, count(restored, Opcode.SUB_LONG));
        var run = new NpNumericInterpreter(dex(restored));
        for (long x : new long[]{Long.MIN_VALUE, Long.MAX_VALUE, -1, 0, 1})
            for (long y : new long[]{Long.MIN_VALUE, Long.MAX_VALUE, -1, 0, 1})
                assertEquals(x + y, run.run(Signatures.of(restored), x, y));
    }
    private Method splitArithmetic(boolean negated, int amount, String variant) {
        var b = new MethodImplementationBuilder(7);
        if (variant.equals("join")) {
            Fixtures.integer(b, 3, 7);
            b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 4, b.getLabel("read")));
        }
        Fixtures.go(b, "start");
        b.addLabel("finish");
        Fixtures.integer(b, 2, negated ? 0 : amount);
        b.addInstruction(new BuilderInstruction23x(negated ? Opcode.SUB_INT : Opcode.ADD_INT, 0, 2, 0));
        if (variant.equals("live")) b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 0, 0, 3));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("combine");
        b.addInstruction(new BuilderInstruction23x(negated ? Opcode.SUB_INT : Opcode.ADD_INT, 0, 3, 1));
        Fixtures.go(b, "finish");
        b.addLabel("read"); b.addLabel("try");
        b.addInstruction(new BuilderInstruction23x(Opcode.AGET_BYTE, 1, 5, 6));
        b.addLabel("tryEnd"); Fixtures.go(b, "combine");
        b.addLabel("start");
        Fixtures.integer(b, 2, negated ? 0 : -amount);
        b.addInstruction(new BuilderInstruction23x(negated ? Opcode.SUB_INT : Opcode.ADD_INT, 0, negated ? 2 : 4, negated ? 4 : 2));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 3, 0));
        if (variant.equals("observer")) b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 3,
                new ImmutableFieldReference("Lsample/Test;", "seen", "I")));
        Fixtures.go(b, "read");
        if (variant.equals("handler")) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 2));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 3));
            b.addCatch("Ljava/lang/Exception;", b.getLabel("try"), b.getLabel("tryEnd"), b.getLabel("handler"));
        }
        return Fixtures.method("splitArithmetic", List.of(param("I"), param("[B"), param("I")), "I", b.getMethodImplementation());
    }
    @Test public void cancelsRegisterOffsetsAndNegationsAcrossUniqueGotoEdgesAndReads() throws Exception {
        for (boolean negated : new boolean[]{false, true}) for (int amount : new int[]{8, Integer.MIN_VALUE}) {
            Method original = splitArithmetic(negated, amount, "plain"), restored = rewrite(original);
            assertEquals(0, count(restored, Opcode.SUB_INT));
            assertEquals(1, count(restored, Opcode.ADD_INT));
            var run = new NpNumericInterpreter(dex(restored));
            for (int x : new int[]{Integer.MIN_VALUE, Integer.MAX_VALUE, -129, -1, 0, 1, 128})
                for (byte y : new byte[]{Byte.MIN_VALUE, -1, 0, 1, Byte.MAX_VALUE})
                    assertEquals(x + y, run.run(Signatures.of(restored), x, new byte[]{y}, 0));
            Path file = Files.createTempFile("np-split-arithmetic-", ".dex");
            try { Files.delete(file); DexFiles.write(file, dex(restored));
                assertEquals(0, new DexEngine(List.of(new InstructionTransformer()), 10).transform(DexFiles.read(file)).changedMethods());
            } finally { Files.deleteIfExists(file); }
        }
    }
    @Test public void splitArithmeticRetainsObservedLiveJoinedAndExceptionalValues() {
        for (boolean negated : new boolean[]{false, true}) for (String variant : List.of("observer", "live", "join", "handler")) {
            Method original = splitArithmetic(negated, 8, variant), restored = rewrite(original);
            if (variant.equals("join")) assertEquals(1, count(restored, Opcode.IF_EQZ));
            if (variant.equals("handler")) assertEquals(1, restored.getImplementation().getTryBlocks().size());
            if (negated && variant.equals("live")) assertTrue(count(restored, Opcode.SUB_INT) >= 2);
            var before = new NpNumericInterpreter(dex(original)); var after = new NpNumericInterpreter(dex(restored));
            for (int x : new int[]{Integer.MIN_VALUE, -1, 0, 1, Integer.MAX_VALUE})
                for (byte[] array : new byte[][]{null, new byte[0], new byte[]{-128, 127}}) {
                    Object a, b;
                    try { a = before.run(Signatures.of(original), x, array, 0); } catch (RuntimeException error) { a = error.getClass(); }
                    try { b = after.run(Signatures.of(restored), x, array, 0); } catch (RuntimeException error) { b = error.getClass(); }
                    assertEquals(variant, a, b);
                    if (variant.equals("observer")) {
                        assertEquals(negated ? -x : x - 8, before.field("Lsample/Test;->seen:I"));
                        assertEquals(before.field("Lsample/Test;->seen:I"), after.field("Lsample/Test;->seen:I"));
                    }
                }
        }
    }
    private Method splitMask(boolean wide, String variant) {
        var b = new MethodImplementationBuilder(wide ? 10 : 6);
        int source = wide ? 7 : 4, selector = wide ? 9 : 5;
        if (variant.equals("join")) {
            if (wide) b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 2, 7));
            else Fixtures.integer(b, 2, 7);
            b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, selector, b.getLabel("not")));
        }
        Fixtures.go(b, "start");
        b.addLabel("and");
        b.addInstruction(new BuilderInstruction23x(wide ? Opcode.AND_LONG : Opcode.AND_INT, 0, 0, 2));
        if (variant.equals("live")) b.addInstruction(new BuilderInstruction23x(wide ? Opcode.ADD_LONG : Opcode.ADD_INT, 0, 0, 2));
        b.addInstruction(new BuilderInstruction11x(wide ? Opcode.RETURN_WIDE : Opcode.RETURN, 0));
        b.addLabel("not");
        b.addInstruction(new BuilderInstruction12x(wide ? Opcode.NOT_LONG : Opcode.NOT_INT, 0, 2));
        if (variant.equals("observer")) b.addInstruction(new BuilderInstruction21c(wide ? Opcode.SPUT_WIDE : Opcode.SPUT, 0,
                new ImmutableFieldReference("Lsample/Test;", "seen", wide ? "J" : "I")));
        Fixtures.go(b, "and");
        b.addLabel("start");
        if (variant.equals("literal")) {
            if (wide) b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 2, Long.MIN_VALUE));
            else Fixtures.integer(b, 2, Integer.MIN_VALUE);
        } else b.addInstruction(new BuilderInstruction32x(wide ? Opcode.MOVE_WIDE_16 : Opcode.MOVE_16, 2, source));
        Fixtures.go(b, "not");
        return Fixtures.method("splitMask", List.of(param(wide ? "J" : "I"), param("I")), wide ? "J" : "I", b.getMethodImplementation());
    }
    private static Object numeric(boolean wide, long value) {
        if (wide) return value;
        return (int)value;
    }
    @Test public void restoresIntAndLongMasksAcrossReversedPhysicalBlockOrder() throws Exception {
        for (boolean wide : new boolean[]{false, true}) for (String variant : List.of("plain", "literal")) {
            Method restored = rewrite(splitMask(wide, variant));
            assertEquals(0, count(restored, wide ? Opcode.NOT_LONG : Opcode.NOT_INT));
            assertEquals(0, count(restored, wide ? Opcode.AND_LONG : Opcode.AND_INT));
            var run = new NpNumericInterpreter(dex(restored));
            for (long value : new long[]{Long.MIN_VALUE, Integer.MIN_VALUE, -1, 0, 1, Integer.MAX_VALUE, Long.MAX_VALUE})
                assertEquals(0L, ((Number)run.run(Signatures.of(restored), numeric(wide, value), 1)).longValue());
            Path file = Files.createTempFile("np-split-mask-", ".dex");
            try { Files.delete(file); DexFiles.write(file, dex(restored));
                assertEquals(0, new DexEngine(List.of(new InstructionTransformer()), 10).transform(DexFiles.read(file)).changedMethods());
            } finally { Files.deleteIfExists(file); }
        }
    }
    @Test public void splitMasksPreserveObserversJoinsAndLiveWideValues() {
        for (boolean wide : new boolean[]{false, true}) for (String variant : List.of("observer", "join", "live")) {
            Method original = splitMask(wide, variant), restored = rewrite(original);
            if (variant.equals("join")) assertEquals(1, count(restored, Opcode.IF_EQZ));
            var before = new NpNumericInterpreter(dex(original)); var run = new NpNumericInterpreter(dex(restored));
            for (long value : new long[]{Long.MIN_VALUE, -1, 0, 1, Long.MAX_VALUE})
                for (int selector : new int[]{0, 1}) {
                    Object input = numeric(wide, value);
                    Object expected = before.run(Signatures.of(original), input, selector);
                    assertEquals(variant, expected, run.run(Signatures.of(restored), input, selector));
                    assertEquals(variant.equals("live") ? ((Number)input).longValue() : 0L, ((Number)expected).longValue());
                    if (variant.equals("observer")) {
                        String field = "Lsample/Test;->seen:" + (wide ? "J" : "I");
                        assertEquals(numeric(wide, ~((Number)input).longValue()), before.field(field));
                        assertEquals(before.field(field), run.field(field));
                    }
                }
        }
    }
    // Variants exercise real observation points, exceptional successors and DEX encoding.
    private Method offset(String variant) {
        var b = new MethodImplementationBuilder(7);
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 4, 23));
        if (variant.equals("observer")) b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0,
                new ImmutableFieldReference("Lsample/Test;", "seen", "I")));
        if (variant.equals("branch")) b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 4, b.getLabel("combine")));
        b.addLabel("try");
        b.addInstruction(new BuilderInstruction23x(Opcode.AGET_BYTE, 1, 5, 6));
        b.addLabel("end"); b.addLabel("combine");
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 1, 1, 0));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 2, 1, -23));
        if (variant.equals("live")) b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 2, 2, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
        if (variant.equals("handler")) {
            b.addLabel("catch"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 3));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
            b.addCatch("Ljava/lang/Exception;", b.getLabel("try"), b.getLabel("end"), b.getLabel("catch"));
        }
        return Fixtures.method("offset", List.of(param("I"), param("[B"), param("I")), "I", b.getMethodImplementation());
    }
    @Test public void cancelsOffsetsAcrossArrayReadPreservingResultsAndExceptions() throws Exception {
        Method original = offset("plain"), restored = rewrite(original);
        assertEquals(0, count(restored, Opcode.ADD_INT_LIT8)); assertEquals(1, count(restored, Opcode.AGET_BYTE));
        Path folder = Files.createTempDirectory("instruction-residual-");
        Path file = folder.resolve("result.dex");
        try {
            DexFiles.write(file, dex(restored));
            var result = DexFiles.read(file); var run = new NpNumericInterpreter(result);
            for (int x : new int[]{Integer.MIN_VALUE, Integer.MAX_VALUE, -24, -1, 0, 23})
                for (byte value : new byte[]{Byte.MIN_VALUE, -1, 0, 1, Byte.MAX_VALUE})
                    assertEquals(x + value, run.run(Signatures.of(restored), x, new byte[]{value}, 0));
            assertThrows(NullPointerException.class, () -> run.run(Signatures.of(restored), 8, null, 0));
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> run.run(Signatures.of(restored), 8, new byte[0], 0));
            assertEquals(0, new DexEngine(List.of(new InstructionTransformer()), 10).transform(result).changedMethods());
        } finally { Files.deleteIfExists(file); Files.deleteIfExists(folder); }
    }
    @Test public void keepsObservedOffsetsAndDoesNotCrossHandlersOrBranchEntries() {
        for (String variant : List.of("observer", "live", "handler", "branch")) {
            Method original = offset(variant), restored = rewrite(original);
            assertEquals(variant, 2, count(restored, Opcode.ADD_INT_LIT8));
            assertEquals(variant, original.getImplementation().getTryBlocks().size(), restored.getImplementation().getTryBlocks().size());
        }
    }
    private static Method constructorAlias(Opcode move, boolean range, boolean transitive, boolean protectedCode, String variant) {
        int alias = move == Opcode.MOVE_OBJECT ? 14 : 42;
        int receiver = move == Opcode.MOVE_OBJECT_16 ? 300 : 0;
        int registers = receiver == 300 ? 303 : 46, input = registers - 1;
        var b = new MethodImplementationBuilder(registers);
        var type = new ImmutableTypeReference("Ljava/lang/StringBuilder;");
        var init = new ImmutableMethodReference(type.getType(), "<init>", List.of("I"), "V");
        if (variant.equals("incoming")) {
            b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_16, 5, input));
            b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 5, b.getLabel("alternate")));
        }
        b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, alias, type));
        if (transitive) b.addInstruction(new BuilderInstruction22x(Opcode.MOVE_OBJECT_FROM16, 13, alias));
        int source = transitive ? 13 : alias;
        if (move == Opcode.MOVE_OBJECT) b.addInstruction(new BuilderInstruction12x(move, receiver, source));
        else if (move == Opcode.MOVE_OBJECT_FROM16) b.addInstruction(new BuilderInstruction22x(move, receiver, source));
        else b.addInstruction(new BuilderInstruction32x(move, receiver, source));
        b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_16, receiver + 1, input));
        if (variant.equals("overwrite")) Fixtures.integer(b, alias, 0);
        if (variant.equals("split")) Fixtures.go(b, "try");
        b.addLabel("try");
        if (range) b.addInstruction(new BuilderInstruction3rc(Opcode.INVOKE_DIRECT_RANGE, receiver, 2, init));
        else b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 2, receiver, receiver + 1, 0, 0, 0, init));
        b.addLabel("join");
        b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_OBJECT_16, 2, variant.equals("dead") ? receiver : alias));
        b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_OBJECT_16, 3, receiver));
        b.addInstruction(new BuilderInstruction22t(Opcode.IF_NE, 2, 3, b.getLabel("different")));
        if (transitive) b.addInstruction(new BuilderInstruction22t(Opcode.IF_NE, 2, 13, b.getLabel("different")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 2, 0, 0, 0, 0,
                new ImmutableMethodReference(type.getType(), "capacity", List.of(), "I")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 4));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 4));
        b.addLabel("different"); Fixtures.integer(b, 4, -99); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 4));
        if (protectedCode) {
            b.addLabel("catch"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 4));
            Fixtures.integer(b, 4, -1001); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 4));
            b.addCatch("Ljava/lang/RuntimeException;", b.getLabel("try"), b.getLabel("join"), b.getLabel("catch"));
        }
        if (variant.equals("incoming")) {
            b.addLabel("alternate");
            b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, alias, type));
            Fixtures.integer(b, alias + 1, 0);
            b.addInstruction(new BuilderInstruction3rc(Opcode.INVOKE_DIRECT_RANGE, alias, 2, init));
            Fixtures.integer(b, 4, 0);
            b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_OBJECT_16, receiver, 4));
            Fixtures.go(b, "join");
        }
        return Fixtures.method("constructorAlias", List.of(param("I")), "I", b.getMethodImplementation());
    }
    private static List<Instruction> instructions(Method method) {
        List<Instruction> result = new ArrayList<>(); method.getImplementation().getInstructions().forEach(result::add); return result;
    }
    @Test public void normalizesLiveConstructorAliasesAcrossMoveAndInvokeEncodings() throws Exception {
        Path folder = Files.createTempDirectory("constructor-alias-"); Path file = folder.resolve("result.dex");
        try {
            for (Opcode move : List.of(Opcode.MOVE_OBJECT, Opcode.MOVE_OBJECT_FROM16, Opcode.MOVE_OBJECT_16))
                for (boolean range : new boolean[]{false, true}) {
                    if (move == Opcode.MOVE_OBJECT_16 && !range) continue;
                    for (boolean transitive : new boolean[]{false, true}) for (boolean protectedCode : new boolean[]{false, true}) {
                        Method original = constructorAlias(move, range, transitive, protectedCode, "plain"), restored = rewrite(original);
                        assertEquals(instructions(original).size() + (transitive ? 2 : 1), instructions(restored).size());
                        CodeGraph before = new CodeGraph(original.getImplementation()), after = new CodeGraph(restored.getImplementation());
                        int ctor = -1;
                        for (int i = 0; i < after.size(); i++) if (after.at(i).getOpcode() == Opcode.INVOKE_DIRECT
                                || after.at(i).getOpcode() == Opcode.INVOKE_DIRECT_RANGE) { ctor = i; break; }
                        assertTrue(ctor >= 0); assertEquals(Opcode.MOVE_OBJECT_16, after.at(ctor + 1).getOpcode());
                        assertEquals(protectedCode ? 1 : 0, after.protection(ctor).size());
                        assertEquals(before.at(ctor).getOpcode(), after.at(ctor).getOpcode());
                        DexFiles.write(file, dex(restored));
                        assertEquals(0, new DexEngine(List.of(new InstructionTransformer()), 10).transform(DexFiles.read(file)).changedMethods());
                        Files.delete(file);
                    }
                }
        } finally { Files.deleteIfExists(file); Files.deleteIfExists(folder); }
    }
    @Test public void leavesDeadOverwrittenAndUnprovenConstructorAliasesAlone() {
        for (String variant : List.of("dead", "overwrite", "split")) {
            Method original = constructorAlias(Opcode.MOVE_OBJECT_FROM16, true, false, true, variant), restored = rewrite(original);
            assertEquals(variant, MethodFingerprint.of(new DexContext(dex(original)), original),
                    MethodFingerprint.of(new DexContext(dex(restored)), restored));
        }
    }
    @Test public void incomingEdgesSkipConstructorAliasCopies() {
        Method original = constructorAlias(Opcode.MOVE_OBJECT_16, true, false, true, "incoming"), restored = rewrite(original);
        assertEquals(instructions(original).size() + 1, instructions(restored).size());
        CodeGraph graph = new CodeGraph(restored.getImplementation());
        for (int i = 0; i < graph.size(); i++) if (CodeGraph.isGoto(graph.at(i).getOpcode())) {
            var target = (TwoRegisterInstruction)graph.at(graph.successors(i).get(0));
            assertEquals(Opcode.MOVE_OBJECT_16, target.getOpcode()); assertEquals(2, target.getRegisterA()); assertEquals(42, target.getRegisterB());
        }
        assertEquals(0, new DexEngine(List.of(new InstructionTransformer()), 10).transform(dex(restored)).changedMethods());
    }
    private static Method constructorReceiver(Opcode move, boolean protectedCode, String variant) {
        var b = new MethodImplementationBuilder(8);
        if (variant.equals("overwritten")) Fixtures.integer(b, 0, 12);
        if (variant.equals("receiver-write")) b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 6, 6));
        b.addLabel("start");
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 7, b.getLabel("alternate")));
        receiverCopy(b, move); Fixtures.go(b, "join");
        b.addLabel("alternate"); receiverCopy(b, move);
        b.addLabel("join");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/Object;", "<init>", List.of(), "V")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 6, 7, 0, 0, 0,
                new ImmutableMethodReference("LReceiverAliasProbe;", "observe", List.of("Ljava/lang/Object;", "I"), "V")));
        b.addLabel("end"); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        if (protectedCode) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 4));
            b.addInstruction(new BuilderInstruction11x(Opcode.THROW, 4));
            b.addCatch("Ljava/lang/Throwable;", b.getLabel("start"), b.getLabel("end"), b.getLabel("handler"));
        }
        return new ImmutableMethod("Lsample/Test;", "<init>", List.of(param("I")), "V",
                AccessFlags.PUBLIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(), Set.of(), Set.of(), b.getMethodImplementation());
    }
    private static void receiverCopy(MethodImplementationBuilder b, Opcode move) {
        if (move == Opcode.MOVE_OBJECT) b.addInstruction(new BuilderInstruction12x(move, 0, 6));
        else if (move == Opcode.MOVE_OBJECT_FROM16) b.addInstruction(new BuilderInstruction22x(move, 0, 6));
        else b.addInstruction(new BuilderInstruction32x(move, 0, 6));
    }
    @Test public void mergesRepeatedThisCopiesBeforeConstructorBranches() throws Exception {
        for (Opcode move : List.of(Opcode.MOVE_OBJECT, Opcode.MOVE_OBJECT_FROM16, Opcode.MOVE_OBJECT_16))
            for (boolean protectedCode : List.of(false, true)) {
                Method original = constructorReceiver(move, protectedCode, "plain"), output = rewrite(original);
                CodeGraph graph = new CodeGraph(output.getImplementation());
                assertEquals(instructions(original).size() - 1, graph.size());
                assertEquals(Opcode.MOVE_OBJECT_16, graph.at(0).getOpcode());
                assertEquals(0, ((TwoRegisterInstruction) graph.at(0)).getRegisterA());
                assertEquals(6, ((TwoRegisterInstruction) graph.at(0)).getRegisterB());
                assertTrue(graph.protection(0).isEmpty());
                for (int i = 0; i < graph.size(); i++) if (graph.at(i).getOpcode() == Opcode.INVOKE_DIRECT || graph.at(i).getOpcode() == Opcode.INVOKE_STATIC)
                    assertEquals(protectedCode ? 1 : 0, graph.protection(i).size());
                Path file = Files.createTempFile("this-alias-", ".dex");
                try {
                    Files.delete(file); DexFiles.write(file, dex(output));
                    assertEquals(0, new DexEngine(List.of(new InstructionTransformer()), 10).transform(DexFiles.read(file)).changedMethods());
                } finally { Files.deleteIfExists(file); }
            }
    }
    @Test public void retainsConstructorAliasesWithAdditionalRegisterDefinitions() {
        for (String variant : List.of("overwritten", "receiver-write")) {
            Method original = constructorReceiver(Opcode.MOVE_OBJECT_16, false, variant), output = rewrite(original);
            assertEquals(MethodFingerprint.of(new DexContext(dex(original)), original), MethodFingerprint.of(new DexContext(dex(output)), output));
        }
    }
    private static Method crossBlockMask(boolean unknown, boolean observed) {
        var b = new MethodImplementationBuilder(8);
        if (unknown) b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 1, 7));
        else Fixtures.integer(b, 1, 48784);
        Fixtures.go(b, "calculate"); b.addLabel("calculate");
        b.addInstruction(new BuilderInstruction12x(Opcode.NOT_INT, 2, unknown ? 6 : 7));
        b.addInstruction(new BuilderInstruction23x(Opcode.AND_INT, 2, 2, 1));
        Fixtures.integer(b, 3, ~48784);
        b.addInstruction(new BuilderInstruction23x(Opcode.AND_INT, 4, unknown ? 6 : 7, 3));
        b.addInstruction(new BuilderInstruction23x(Opcode.OR_INT, 0, 4, 2));
        if (observed) b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 0, 0, 2));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        return Fixtures.method("crossBlockMask", unknown ? List.of(param("I"), param("I")) : List.of(param("I")), "I", b.getMethodImplementation());
    }
    @Test public void restoresExpandedXorWithMaskProvenAcrossBlocks() throws Exception {
        Method original = crossBlockMask(false, false), output = rewrite(original);
        assertEquals(0, count(output, Opcode.NOT_INT)); assertEquals(0, count(output, Opcode.OR_INT));
        for (int n : new int[]{Integer.MIN_VALUE, Integer.MAX_VALUE, -1, 0, 1, 48784}) {
            assertEquals(n ^ 48784, new NpNumericInterpreter(dex(original)).run(Signatures.of(original), n));
            assertEquals(n ^ 48784, new NpNumericInterpreter(dex(output)).run(Signatures.of(output), n));
        }
    }
    @Test public void retainsUnknownMasksAndObservedIntermediateValues() {
        for (Method original : List.of(crossBlockMask(true, false), crossBlockMask(false, true))) {
            Method output = rewrite(original); assertEquals(1, count(output, Opcode.OR_INT));
            for (int n : new int[]{Integer.MIN_VALUE, -1, 0, 1, Integer.MAX_VALUE}) {
                Object[] args = original.getParameterTypes().size() == 2 ? new Object[]{n, n + 1} : new Object[]{n};
                assertEquals(new NpNumericInterpreter(dex(original)).run(Signatures.of(original), args),
                        new NpNumericInterpreter(dex(output)).run(Signatures.of(output), args));
            }
        }
    }
}
