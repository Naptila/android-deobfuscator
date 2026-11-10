package me.naptila.deobfuscator;

import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import java.nio.file.Path;
import java.util.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.debug.LineNumber;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.jf.dexlib2.immutable.value.ImmutableIntEncodedValue;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class ConditionalCopiesTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    private static final String OWNER = "Lsample/Test;";
    private static final ImmutableFieldReference TRACE = new ImmutableFieldReference(OWNER, "trace", "I");
    private static final ImmutableMethodReference EFFECT = new ImmutableMethodReference(OWNER, "effect", List.of("I"), "I");
    private static final int[] VALUES = {Integer.MIN_VALUE, -101, -1, 0, 1, 101, Integer.MAX_VALUE};
    private List<ImmutableMethodParameter> parameters(String... types) {
        return Arrays.stream(types).map(t -> new ImmutableMethodParameter(t, Set.of(), null)).toList();
    }
    private void move(MethodImplementationBuilder b, Opcode op, int target, int source) {
        b.addInstruction(op == Opcode.MOVE || op == Opcode.MOVE_OBJECT || op == Opcode.MOVE_WIDE
                ? new BuilderInstruction12x(op, target, source)
                : op == Opcode.MOVE_FROM16 || op == Opcode.MOVE_OBJECT_FROM16
                    ? new BuilderInstruction22x(op, target, source) : new BuilderInstruction32x(op, target, source));
    }
    private boolean two(Opcode op) {
        return op == Opcode.IF_EQ || op == Opcode.IF_NE || op == Opcode.IF_LT || op == Opcode.IF_LE || op == Opcode.IF_GT || op == Opcode.IF_GE;
    }
    private Method fixture(Opcode copy, Opcode condition, boolean taken, boolean object, String hazard) {
        var b = new MethodImplementationBuilder(10);
        Fixtures.integer(b, 2, 0); b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 2, TRACE));
        if (hazard.equals("join")) {
            Fixtures.integer(b, 0, 77);
            b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 9, b.getLabel("guard")));
        }
        b.addLineNumber(10); move(b, copy, 0, 8);
        if (hazard.equals("local")) b.addStartLocal(0, new ImmutableStringReference("saved"), new ImmutableTypeReference("I"), null);
        if (hazard.equals("write-source")) Fixtures.integer(b, 8, 123);
        if (hazard.equals("wide-source")) b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 7, 123));
        if (hazard.equals("write-destination")) Fixtures.integer(b, 0, 123);
        if (hazard.equals("read-destination")) b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, TRACE));
        if (hazard.equals("loop")) {
            b.addLabel("loop"); Fixtures.go(b, "loop");
        }
        if (hazard.equals("budget")) for (int i = 0; i < 70; i++) b.addInstruction(new BuilderInstruction10x(Opcode.NOP));
        if (hazard.equals("constructor")) {
            b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 2, new ImmutableTypeReference("Ljava/lang/Object;")));
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 2, 0, 0, 0, 0,
                    new ImmutableMethodReference("Ljava/lang/Object;", "<init>", List.of(), "V")));
        }
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 9, 0, 0, 0, 0, EFFECT));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 1));
        Fixtures.go(b, "guard");
        b.addLabel("guard"); b.addLineNumber(20);
        b.addInstruction(two(condition) ? new BuilderInstruction22t(condition, 9, 8, b.getLabel("taken"))
                : new BuilderInstruction21t(condition, 9, b.getLabel("taken")));
        b.addLabel("fall"); b.addLineNumber(30);
        if (taken && !hazard.equals("both")) {
            if (object) Fixtures.string(b, 0, "fallback"); else Fixtures.integer(b, 0, -17);
        }
        b.addInstruction(new BuilderInstruction11x(object ? Opcode.RETURN_OBJECT : Opcode.RETURN, 0));
        b.addLabel("taken"); b.addLineNumber(40);
        if (!taken && !hazard.equals("both")) {
            if (object) Fixtures.string(b, 0, "fallback"); else Fixtures.integer(b, 0, -17);
        }
        b.addInstruction(new BuilderInstruction11x(object ? Opcode.RETURN_OBJECT : Opcode.RETURN, 0));
        return Fixtures.method("flow", parameters(object ? "Ljava/lang/String;" : "I", "I"), object ? "Ljava/lang/String;" : "I", b.getMethodImplementation());
    }
    private DexFile dex(Method method) {
        var b = new MethodImplementationBuilder(3);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, TRACE));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, 1));
        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, TRACE));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
        Method effect = Fixtures.method("effect", parameters("I"), "I", b.getMethodImplementation());
        Field trace = new ImmutableField(OWNER, "trace", "I", AccessFlags.STATIC.getValue(), new ImmutableIntEncodedValue(0), Set.of(), Set.of());
        return new ImmutableDexFile(Opcodes.forApi(28), List.of(new ImmutableClassDef(OWNER, AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;", List.of(), "Copies.java", Set.of(), List.of(trace), List.of(method, effect))));
    }
    private Method serialize(Method method, String name) throws Exception {
        Path path = directory.getRoot().toPath().resolve(name + ".dex"); DexFiles.write(path, dex(method));
        return new DexContext(DexFiles.read(path)).findMethod(Signatures.of(method)).orElseThrow();
    }
    private void equivalent(Method before, Method after) {
        var original = new NpNumericInterpreter(dex(before)); var result = new NpNumericInterpreter(dex(after));
        for (int value : VALUES) for (int selector : VALUES) {
            assertEquals(original.run(Signatures.of(before), value, selector), result.run(Signatures.of(after), value, selector));
            assertEquals(original.field(Signatures.of(TRACE)), result.field(Signatures.of(TRACE)));
        }
    }
    @Test public void preservesAllIntegerConditionsBothEdgesAndSideEffectsAfterSerialization() throws Exception {
        int index = 0;
        for (Opcode copy : List.of(Opcode.MOVE, Opcode.MOVE_FROM16, Opcode.MOVE_16))
            for (Opcode condition : List.of(Opcode.IF_EQ, Opcode.IF_NE, Opcode.IF_LT, Opcode.IF_LE, Opcode.IF_GT, Opcode.IF_GE,
                    Opcode.IF_EQZ, Opcode.IF_NEZ, Opcode.IF_LTZ, Opcode.IF_LEZ, Opcode.IF_GTZ, Opcode.IF_GEZ))
                for (boolean taken : List.of(false, true)) {
                    Method input = fixture(copy, condition, taken, false, ""); var context = new MethodContext(input);
                    assertEquals(1, ConditionalCopies.run(context)); assertEquals(0, ConditionalCopies.run(context));
                    Method output = serialize(context.finish(), "integer-" + index++);
                    equivalent(input, output); assertEquals(0, ConditionalCopies.run(new MethodContext(output)));
                }
    }
    @Test public void preservesReferenceIdentityNullAndAllObjectCopyEncodings() throws Exception {
        int index = 0;
        for (Opcode copy : List.of(Opcode.MOVE_OBJECT, Opcode.MOVE_OBJECT_FROM16, Opcode.MOVE_OBJECT_16))
            for (boolean taken : List.of(false, true)) {
                Method input = fixture(copy, Opcode.IF_EQZ, taken, true, ""); var context = new MethodContext(input);
                assertEquals(1, ConditionalCopies.run(context)); Method output = serialize(context.finish(), "object-" + index++);
                var before = new NpNumericInterpreter(dex(input)); var after = new NpNumericInterpreter(dex(output));
                for (Object value : new Object[]{null, new String(""), new String("中文🙂")}) for (int selector : VALUES) {
                    Object expected = before.run(Signatures.of(input), value, selector);
                    Object actual = after.run(Signatures.of(output), value, selector);
                    if (expected == value) assertSame(value, actual); else assertEquals(expected, actual);
                    assertEquals(1, after.field(Signatures.of(TRACE)));
                }
            }
    }
    @Test public void refusesWritesReadsSharedEntryAndBothLiveEdges() {
        for (String hazard : List.of("write-source", "wide-source", "write-destination", "read-destination", "join", "both")) {
            Method input = fixture(Opcode.MOVE, Opcode.IF_EQZ, true, false, hazard); var context = new MethodContext(input);
            assertEquals(hazard, 0, ConditionalCopies.run(context)); equivalent(input, context.finish());
        }
    }
    @Test public void refusesLoopsOverBudgetPathsConstructorsAndVisibleDebugLocals() {
        for (String hazard : List.of("loop", "budget", "constructor", "local")) {
            Method input = fixture(Opcode.MOVE, Opcode.IF_EQZ, true, false, hazard); var context = new MethodContext(input);
            assertEquals(hazard, 0, ConditionalCopies.run(context));
            assertEquals(input.getImplementation().getRegisterCount(), context.finish().getImplementation().getRegisterCount());
        }
    }
    private Method exceptionFixture(boolean protect) {
        var b = new MethodImplementationBuilder(6);
        move(b, Opcode.MOVE, 0, 3); Fixtures.integer(b, 2, 0);
        b.addLabel("start");
        b.addInstruction(new BuilderInstruction23x(Opcode.AGET_BYTE, 1, 4, 2));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 5, b.getLabel("use")));
        Fixtures.integer(b, 0, 7); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("use"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0)); b.addLabel("end");
        if (protect) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
            b.addCatch("Ljava/lang/Exception;", b.getLabel("start"), b.getLabel("end"), b.getLabel("handler"));
        }
        return Fixtures.method("flow", parameters("I", "[B", "I"), "I", b.getMethodImplementation());
    }
    @Test public void keepsAssignmentsVisibleToExceptionHandlers() throws Exception {
        Method input = exceptionFixture(true); var context = new MethodContext(input); assertEquals(0, ConditionalCopies.run(context));
        Method output = serialize(context.finish(), "caught");
        var before = new NpNumericInterpreter(dex(input)); var after = new NpNumericInterpreter(dex(output));
        for (Object array : new Object[]{null, new byte[0], new byte[]{1}}) for (int selector : VALUES)
            assertEquals(before.run(Signatures.of(input), 41, array, selector), after.run(Signatures.of(output), 41, array, selector));
    }
    @Test public void retainsUncaughtThrowAndNormalResults() throws Exception {
        Method input = exceptionFixture(false); var context = new MethodContext(input); assertEquals(1, ConditionalCopies.run(context));
        Method output = serialize(context.finish(), "uncaught");
        var before = new NpNumericInterpreter(dex(input)); var after = new NpNumericInterpreter(dex(output));
        for (int selector : VALUES) {
            assertEquals(before.run(Signatures.of(input), 41, new byte[]{1}, selector), after.run(Signatures.of(output), 41, new byte[]{1}, selector));
            assertThrows(NullPointerException.class, () -> before.run(Signatures.of(input), 41, null, selector));
            assertThrows(NullPointerException.class, () -> after.run(Signatures.of(output), 41, null, selector));
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> after.run(Signatures.of(output), 41, new byte[0], selector));
        }
    }
    @Test public void preservesLineMarkersAndRegisterCount() throws Exception {
        Method input = fixture(Opcode.MOVE, Opcode.IF_EQZ, true, false, ""); var context = new MethodContext(input);
        assertEquals(1, ConditionalCopies.run(context)); Method output = serialize(context.finish(), "debug-lines");
        List<Integer> lines = new ArrayList<>();
        for (var debug : output.getImplementation().getDebugItems()) if (debug instanceof LineNumber line) lines.add(line.getLineNumber());
        assertEquals(List.of(10, 20, 30, 40), lines);
        assertEquals(input.getImplementation().getRegisterCount(), output.getImplementation().getRegisterCount());
    }
    @Test public void preservesWideCopiesWithoutMovingHalfAValue() throws Exception {
        var b = new MethodImplementationBuilder(11);
        move(b, Opcode.MOVE_WIDE, 0, 8);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 10, b.getLabel("use")));
        b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 0, -17));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
        b.addLabel("use"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
        Method input = Fixtures.method("flow", parameters("J", "I"), "J", b.getMethodImplementation());
        var context = new MethodContext(input); assertEquals(0, ConditionalCopies.run(context));
        Method output = serialize(context.finish(), "wide");
        var before = new NpNumericInterpreter(dex(input)); var after = new NpNumericInterpreter(dex(output));
        for (long value : new long[]{Long.MIN_VALUE, -1, 0, 1, Long.MAX_VALUE}) for (int selector : VALUES)
            assertEquals(before.run(Signatures.of(input), value, selector), after.run(Signatures.of(output), value, selector));
    }
    @Test public void supportsCopiesOutsideEightBitAndFourBitRegisterRanges() throws Exception {
        var b = new MethodImplementationBuilder(300);
        move(b, Opcode.MOVE_OBJECT_16, 280, 298);
        move(b, Opcode.MOVE_FROM16, 9, 299);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 9, b.getLabel("use")));
        Fixtures.string(b, 1, "fallback"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 1));
        b.addLabel("use"); move(b, Opcode.MOVE_OBJECT_FROM16, 1, 280);
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 1));
        Method input = Fixtures.method("flow", parameters("Ljava/lang/String;", "I"), "Ljava/lang/String;", b.getMethodImplementation());
        var context = new MethodContext(input); assertEquals(1, ConditionalCopies.run(context));
        Method output = serialize(context.finish(), "high-registers");
        var before = new NpNumericInterpreter(dex(input)); var after = new NpNumericInterpreter(dex(output));
        for (String value : new String[]{null, "", "高位🙂"}) for (int selector : VALUES) {
            assertEquals(before.run(Signatures.of(input), value, selector), after.run(Signatures.of(output), value, selector));
            if (selector == 0) assertSame(value, after.run(Signatures.of(output), value, selector));
        }
        assertEquals(0, ConditionalCopies.run(new MethodContext(output)));
    }
    @Test public void normalCleanupUsesRuleWithNpEvidenceAndConverges() throws Exception {
        Method method = fixture(Opcode.MOVE, Opcode.IF_EQZ, true, false, "");
        var code = new MutableMethodImplementation(method.getImplementation());
        code.addInstruction(0, new BuilderInstruction21c(Opcode.CONST_STRING, 2, new ImmutableStringReference("probe")));
        code.addInstruction(1, new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 2, 0, 0, 0, 0, Fixtures.NP_HASH));
        Method input = new ImmutableMethod(OWNER, method.getName(), method.getParameters(), method.getReturnType(), method.getAccessFlags(),
                method.getAnnotations(), method.getHiddenApiRestrictions(), code);
        var classes = new ArrayList<ClassDef>(Fixtures.npDex().getClasses()); classes.removeIf(c -> c.getType().equals(OWNER));
        classes.addAll(dex(input).getClasses());
        var source = new ImmutableDexFile(Opcodes.forApi(28), classes);
        var result = new Deobfuscator(TransformerRegistry.discover()).transform(source, RunConfiguration.defaults().transformers(), 20);
        assertEquals(0, result.failedMethods()); assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged));
        assertTrue(result.methods().stream().flatMap(m -> m.steps().stream()).flatMap(s -> s.result().notes().stream())
                .anyMatch(n -> n.startsWith("copies delayed to live conditional edges:")));
    }
}
