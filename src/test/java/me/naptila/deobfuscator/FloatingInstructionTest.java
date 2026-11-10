package me.naptila.deobfuscator;

import java.nio.file.*;
import java.util.*;
import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.DexEngine;
import me.naptila.deobfuscator.dex.MethodContext;
import me.naptila.deobfuscator.dex.Signatures;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transformers.np.analysis.NpAnalysis;
import me.naptila.deobfuscator.transformers.np.instructions.*;
import me.naptila.deobfuscator.transformers.np.instructions.InstructionTransformer;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.ImmutableFieldReference;
import org.junit.*;
import static org.junit.Assert.*;

public class FloatingInstructionTest {
    private static ClassDef helper;
    @BeforeClass public static void helper() throws Exception {
        var context = new DexContext(DexFiles.read(Path.of(FloatingInstructionTest.class.getResource("/np-v2/opt.dex").toURI())));
        helper = context.classes().get(NpAnalysis.of(context).model().helpers().owners().iterator().next());
    }
    private static DexFile dex(Method method) {
        var classes = new ArrayList<ClassDef>(Fixtures.dex(method).getClasses()); classes.add(helper);
        return new ImmutableDexFile(Opcodes.forApi(28), classes);
    }
    private static Method rewrite(Method method, boolean enabled) {
        var pass = new InstructionTransformer.Provider().create(new TransformerOptions(Map.of("restoreFloatingPoint", enabled)));
        var result = new DexEngine(List.of(pass), 10).transform(dex(method));
        assertEquals(0, result.failedMethods());
        assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged));
        return new DexContext(result.dex()).findMethod(Signatures.of(method)).orElseThrow();
    }
    private static Method expansion(boolean wide, boolean sum, String barrier) {
        int w = wide ? 2 : 1;
        var b = new MethodImplementationBuilder(6 * w);
        b.addInstruction(wide ? new BuilderInstruction51l(Opcode.CONST_WIDE, 0, sum ? 0 : Double.doubleToLongBits(2))
                : new BuilderInstruction31i(Opcode.CONST, 0, sum ? 0 : Float.floatToIntBits(2)));
        // sum: 0 - ((0 - x) - y); difference: 2 + ((x - 2) - y).
        b.addInstruction(new BuilderInstruction23x(wide ? Opcode.SUB_DOUBLE : Opcode.SUB_FLOAT, w, sum ? 0 : 4*w, sum ? 4*w : 0));
        if (barrier.equals("observer")) b.addInstruction(new BuilderInstruction21c(wide ? Opcode.SPUT_WIDE : Opcode.SPUT, w,
                new ImmutableFieldReference("Lsample/Test;", "observed", wide ? "D" : "F")));
        if (barrier.equals("branch")) b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("middle")));
        if (barrier.equals("conversion")) {
            b.addInstruction(new BuilderInstruction12x(wide ? Opcode.DOUBLE_TO_FLOAT : Opcode.FLOAT_TO_DOUBLE, 2*w, w));
            b.addInstruction(new BuilderInstruction12x(wide ? Opcode.FLOAT_TO_DOUBLE : Opcode.DOUBLE_TO_FLOAT, w, 2*w));
        }
        b.addLabel("middle");
        b.addInstruction(new BuilderInstruction23x(wide ? Opcode.SUB_DOUBLE : Opcode.SUB_FLOAT, w, w, 5*w));
        b.addInstruction(new BuilderInstruction23x(wide ? (sum ? Opcode.SUB_DOUBLE : Opcode.ADD_DOUBLE)
                : (sum ? Opcode.SUB_FLOAT : Opcode.ADD_FLOAT), 2*w, 0, w));
        if (barrier.equals("live")) b.addInstruction(new BuilderInstruction23x(wide ? Opcode.ADD_DOUBLE : Opcode.ADD_FLOAT, 2*w, 2*w, w));
        b.addInstruction(new BuilderInstruction11x(wide ? Opcode.RETURN_WIDE : Opcode.RETURN, 2*w));
        String type = wide ? "D" : "F";
        return Fixtures.method("floating", List.of(new ImmutableMethodParameter(type, Set.of(), null),
                new ImmutableMethodParameter(type, Set.of(), null)), type, b.getMethodImplementation());
    }
    private static List<ImmutableInstructionWrapper> code(Method method) {
        List<ImmutableInstructionWrapper> result = new ArrayList<>();
        for (var i : method.getImplementation().getInstructions()) result.add(new ImmutableInstructionWrapper(i.getOpcode(), i.getCodeUnits()));
        return result;
    }
    private record ImmutableInstructionWrapper(Opcode opcode, int units) {}
    @Test public void defaultsRetainBothPrecisionsAndRejectInvalidOption() {
        for (boolean wide : List.of(false, true)) for (boolean sum : List.of(false, true)) {
            Method original = expansion(wide, sum, "");
            var context = new DexContext(dex(original)); var pass = new InstructionTransformer.Provider().create(TransformerOptions.empty());
            pass.prepare(context);
            assertEquals(0, pass.run(new MethodContext(context, original)).edits());
            assertEquals(code(original), code(rewrite(original, false)));
        }
        assertThrows(IllegalArgumentException.class, () -> new InstructionTransformer.Provider().create(new TransformerOptions(Map.of("restoreFloatingPoint", "true"))));
    }
    @Test public void optInRestoresBothPrecisionsIncludingSpecialValues() {
        double[] values = {0, -0.0, 0.1, 0.2, 1, -1, Double.MIN_VALUE, Double.MAX_VALUE,
                Float.MIN_VALUE, Float.MAX_VALUE, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY};
        for (boolean wide : List.of(false, true)) for (boolean sum : List.of(false, true)) {
            Method original = expansion(wide, sum, ""), restored = rewrite(original, true);
            assertTrue(code(restored).size() < code(original).size());
            var interpreter = new NpNumericInterpreter(dex(restored));
            for (double x : values) for (double y : values) {
                if (wide) {
                    double actual = (Double)interpreter.run(Signatures.of(restored), x, y);
                    assertEquals(Double.doubleToLongBits(sum ? x+y : x-y), Double.doubleToLongBits(actual));
                } else {
                    float a = (float)x, b = (float)y;
                    float actual = (Float)interpreter.run(Signatures.of(restored), a, b);
                    assertEquals(Float.floatToIntBits(sum ? a+b : a-b), Float.floatToIntBits(actual));
                }
            }
        }
    }
    @Test public void recoveryIsExplicitlyNotBitEquivalentToExpandedFloatingCode() {
        for (boolean wide : List.of(false, true)) {
            Method original = expansion(wide, false, ""), restored = rewrite(original, true);
            var before = new NpNumericInterpreter(dex(original)); var after = new NpNumericInterpreter(dex(restored));
            if (wide) {
                assertNotEquals(Double.doubleToLongBits((Double)before.run(Signatures.of(original), 0.1, 0.2)),
                        Double.doubleToLongBits((Double)after.run(Signatures.of(restored), 0.1, 0.2)));
            } else {
                assertNotEquals(Float.floatToIntBits((Float)before.run(Signatures.of(original), 0.1f, 0.2f)),
                        Float.floatToIntBits((Float)after.run(Signatures.of(restored), 0.1f, 0.2f)));
            }
        }
    }
    @Test public void preservesObservationPointsConversionsAndBranchBoundaries() {
        for (boolean wide : List.of(false, true)) for (String barrier : List.of("observer", "branch", "conversion", "live")) {
            Method original = expansion(wide, false, barrier);
            assertEquals(barrier, code(original), code(rewrite(original, true)));
        }
    }
    @Test public void roundTripsDexAndConverges() throws Exception {
        Path folder = Files.createTempDirectory("floating-instructions-"); Path file = folder.resolve("result.dex");
        try {
            DexFiles.write(file, dex(rewrite(expansion(true, true, ""), true)));
            var result = new DexEngine(List.of(new InstructionTransformer(true)), 10).transform(DexFiles.read(file));
            assertEquals(0, result.failedMethods()); assertEquals(0, result.changedMethods());
        } finally { Files.deleteIfExists(file); Files.deleteIfExists(folder); }
    }
    @Test public void retainsIndependentConversionsAcrossCancellingOffsets() {
        for (boolean wide : List.of(false, true)) for (boolean reuse : List.of(false, true)) {
            int w = wide ? 2 : 1;
            var b = new MethodImplementationBuilder(5*w+1);
            b.addInstruction(wide ? new BuilderInstruction51l(Opcode.CONST_WIDE, 0, Double.doubleToLongBits(16))
                    : new BuilderInstruction31i(Opcode.CONST, 0, Float.floatToIntBits(16)));
            b.addInstruction(new BuilderInstruction23x(wide ? Opcode.ADD_DOUBLE : Opcode.ADD_FLOAT, w, 4*w, 0));
            if (reuse) b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_16, 3*w, 5*w));
            b.addInstruction(new BuilderInstruction12x(wide ? Opcode.INT_TO_DOUBLE : Opcode.INT_TO_FLOAT, reuse ? 0 : 2*w, reuse ? 3*w : 5*w));
            b.addInstruction(new BuilderInstruction23x(wide ? Opcode.ADD_DOUBLE : Opcode.ADD_FLOAT, w, w, reuse ? 0 : 2*w));
            if (reuse) b.addInstruction(wide ? new BuilderInstruction51l(Opcode.CONST_WIDE, 0, Double.doubleToLongBits(16))
                    : new BuilderInstruction31i(Opcode.CONST, 0, Float.floatToIntBits(16)));
            b.addInstruction(new BuilderInstruction23x(wide ? Opcode.SUB_DOUBLE : Opcode.SUB_FLOAT, w, w, 0));
            b.addInstruction(new BuilderInstruction11x(wide ? Opcode.RETURN_WIDE : Opcode.RETURN, w));
            String type = wide ? "D" : "F";
            Method original = Fixtures.method("conversion", List.of(new ImmutableMethodParameter(type, Set.of(), null),
                    new ImmutableMethodParameter("I", Set.of(), null)), type, b.getMethodImplementation());
            Method restored = rewrite(original, true);
            assertEquals(1, code(restored).stream().filter(i -> i.opcode == (wide ? Opcode.INT_TO_DOUBLE : Opcode.INT_TO_FLOAT)).count());
            assertEquals(0, code(restored).stream().filter(i -> i.opcode == (wide ? Opcode.SUB_DOUBLE : Opcode.SUB_FLOAT)).count());
            var interpreter = new NpNumericInterpreter(dex(restored));
            for (int n : new int[]{Integer.MIN_VALUE, -1, 0, 1, Integer.MAX_VALUE}) {
                if (wide) assertEquals(Double.doubleToLongBits(0.1 + (double)n),
                        Double.doubleToLongBits((Double)interpreter.run(Signatures.of(restored), 0.1, n)));
                else assertEquals(Float.floatToIntBits(0.1f + (float)n),
                        Float.floatToIntBits((Float)interpreter.run(Signatures.of(restored), 0.1f, n)));
            }
        }
    }
    @Test public void doesNotHoistConversionOverItsFloatingInput() {
        var b = new MethodImplementationBuilder(10);
        b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 0, Double.doubleToLongBits(16)));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_DOUBLE, 2, 8, 0));
        b.addInstruction(new BuilderInstruction12x(Opcode.DOUBLE_TO_FLOAT, 4, 2));
        b.addInstruction(new BuilderInstruction12x(Opcode.FLOAT_TO_DOUBLE, 4, 4));
        b.addInstruction(new BuilderInstruction23x(Opcode.SUB_DOUBLE, 2, 2, 0));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_DOUBLE, 2, 2, 4));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 2));
        Method original = Fixtures.method("dependent", List.of(new ImmutableMethodParameter("D", Set.of(), null)), "D", b.getMethodImplementation());
        assertEquals(code(original), code(rewrite(original, true)));
    }
    @Test public void doesNotTreatOrdinaryVariableCancellationAsNpExpansion() {
        var b = new MethodImplementationBuilder(6);
        b.addInstruction(new BuilderInstruction23x(Opcode.SUB_DOUBLE, 0, 2, 4));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_DOUBLE, 0, 0, 4));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
        Method original = Fixtures.method("ordinary", List.of(new ImmutableMethodParameter("D", Set.of(), null),
                new ImmutableMethodParameter("D", Set.of(), null)), "D", b.getMethodImplementation());
        assertEquals(code(original), code(rewrite(original, true)));
    }
    @Test public void rejectsRemovedExperimentalClassScopeOption() {
        assertThrows(IllegalArgumentException.class, () -> new InstructionTransformer.Provider().create(new TransformerOptions(
                Map.of("floatingPointClasses", List.of("Lsample/Test;")))));
    }
}
