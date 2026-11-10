package me.naptila.deobfuscator;

import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import me.naptila.deobfuscator.transformers.np.controlflow.DispatcherTransformer;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.MethodImplementationBuilder;
import org.jf.dexlib2.builder.SwitchLabelElement;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.immutable.ImmutableMethodParameter;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class DispatcherArithmeticTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();

    private DexEngine.Result transform(DexFile input, boolean full) {
        var specs = full ? RunConfiguration.defaults().transformers() : List.of(new TransformerSpec("np.dispatcher"));
        var result = new Deobfuscator(TransformerRegistry.discover()).transform(input, specs, 20);
        assertEquals(result.methods().toString(), 0, result.failedMethods());
        assertTrue(result.methods().toString(), result.methods().stream().allMatch(DexEngine.MethodReport::converged));
        return result;
    }

    private long switches(Method method) {
        long count = 0;
        for (var instruction : method.getImplementation().getInstructions())
            if (CodeGraph.isSwitch(instruction.getOpcode())) count++;
        return count;
    }

    private int value(Opcode op, int left, int right) {
        return switch (op) {
            case ADD_INT, ADD_INT_2ADDR -> left + right;
            case SUB_INT, SUB_INT_2ADDR -> left - right;
            case XOR_INT, XOR_INT_2ADDR -> left ^ right;
            case MUL_INT -> left * right;
            case DIV_INT -> left / right;
            default -> throw new AssertionError(op);
        };
    }

    private Method shared(Opcode op, boolean unknown, boolean zeroDivisor) {
        return shared(op, unknown, zeroDivisor, false);
    }

    private Method shared(Opcode op, boolean unknown, boolean zeroDivisor, boolean headerConstant) {
        int left = op == Opcode.DIV_INT ? 150 : Integer.MAX_VALUE;
        int right = op == Opcode.DIV_INT ? 3 : 100;
        int otherLeft = op == Opcode.DIV_INT ? -210 : Integer.MIN_VALUE;
        int otherRight = op == Opcode.DIV_INT ? 7 : -100;
        var b = new MethodImplementationBuilder(6);
        Fixtures.string(b, 3, "entry");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 3, 0, 0, 0, 0, Fixtures.NP_HASH));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        Fixtures.go(b, "dispatch");
        b.addLabel("update");
        if (op.name.endsWith("/2addr")) {
            b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 0, 1));
            b.addInstruction(new BuilderInstruction12x(op, 0, 2));
        } else b.addInstruction(new BuilderInstruction23x(op, 0, 1, 2));
        Fixtures.go(b, "dispatch");
        b.addLabel("dispatch");
        if (headerConstant) Fixtures.integer(b, 3, 12345);
        b.addInstruction(new BuilderInstruction31t(Opcode.SPARSE_SWITCH, 0, b.getLabel("payload")));
        Fixtures.go(b, "dispatch");
        b.addLabel("entry");
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ, 5, b.getLabel("negative")));
        if (unknown) b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 1, 5));
        else Fixtures.integer(b, 1, left);
        Fixtures.integer(b, 2, right);
        Fixtures.go(b, "update");
        b.addLabel("negative");
        Fixtures.integer(b, 1, otherLeft);
        Fixtures.integer(b, 2, zeroDivisor ? 0 : otherRight);
        Fixtures.go(b, "update");
        b.addLabel("positiveResult");
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 4, 0, 1));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 4, 4, 2));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 4, 4, 5));
        if (headerConstant) b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 4, 4, 3));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 4));
        b.addLabel("negativeResult");
        b.addInstruction(new BuilderInstruction23x(Opcode.SUB_INT, 4, 0, 1));
        b.addInstruction(new BuilderInstruction23x(Opcode.SUB_INT, 4, 4, 2));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 4, 4, 5));
        if (headerConstant) b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 4, 4, 3));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 4));
        b.addLabel("payload");
        var labels = new ArrayList<>(List.of(
            new SwitchLabelElement("entry".hashCode(), b.getLabel("entry")),
            new SwitchLabelElement(value(op, left, right), b.getLabel("positiveResult")),
            new SwitchLabelElement(value(op, otherLeft, otherRight), b.getLabel("negativeResult"))));
        labels.sort(Comparator.comparingInt(label -> label.key));
        b.addInstruction(new BuilderSparseSwitchPayload(labels));
        return Fixtures.method("shared", List.of(new ImmutableMethodParameter("I", Set.of(), "input")), "I", b.getMethodImplementation());
    }

    @Test public void specializesSharedArithmeticAndPreservesLiveOperandsAndOverflow() throws Exception {
        for (Opcode op : List.of(Opcode.ADD_INT, Opcode.ADD_INT_2ADDR, Opcode.SUB_INT, Opcode.SUB_INT_2ADDR,
                Opcode.XOR_INT, Opcode.XOR_INT_2ADDR, Opcode.MUL_INT, Opcode.DIV_INT)) {
            Method method = shared(op, false, false);
            DexFile input = Fixtures.npDex(method);
            var result = transform(input, false);
            Method output = new DexContext(result.dex()).methods().get(Signatures.of(method));
            assertEquals(op.name, 0, switches(output));
            var before = new NpNumericInterpreter(input);
            var after = new NpNumericInterpreter(result.dex());
            int left = op == Opcode.DIV_INT ? 150 : Integer.MAX_VALUE;
            int right = op == Opcode.DIV_INT ? 3 : 100;
            int otherLeft = op == Opcode.DIV_INT ? -210 : Integer.MIN_VALUE;
            int otherRight = op == Opcode.DIV_INT ? 7 : -100;
            for (int n : new int[]{Integer.MIN_VALUE, -1, 0, 1, 99, Integer.MAX_VALUE}) {
                int expected = n > 0 ? value(op, left, right) + left + right + n
                    : value(op, otherLeft, otherRight) - otherLeft - otherRight + n;
                assertEquals(op.name, expected, before.run(Signatures.of(method), n));
                assertEquals(op.name, expected, after.run(Signatures.of(method), n));
            }
            Path path = directory.getRoot().toPath().resolve(op.name() + ".dex");
            DexFiles.write(path, result.dex());
            assertEquals(op.name, 0, transform(DexFiles.read(path), false).changedMethods());
        }
    }

    @Test public void retainsUnknownArithmeticAndDivisionByZero() {
        Method unknown = shared(Opcode.ADD_INT, true, false);
        DexFile unknownInput = Fixtures.npDex(unknown);
        var unknownResult = transform(unknownInput, false);
        assertTrue(switches(new DexContext(unknownResult.dex()).methods().get(Signatures.of(unknown))) > 0);
        for (int n : new int[]{Integer.MAX_VALUE, -1, 0})
            assertEquals(new NpNumericInterpreter(unknownInput).run(Signatures.of(unknown), n),
                new NpNumericInterpreter(unknownResult.dex()).run(Signatures.of(unknown), n));
        Method method = shared(Opcode.DIV_INT, false, true);
        DexFile input = Fixtures.npDex(method);
        var result = transform(input, false);
        var before = new NpNumericInterpreter(input);
        var after = new NpNumericInterpreter(result.dex());
        for (int n : new int[]{-1, 0}) {
            assertThrows(ArithmeticException.class, () -> before.run(Signatures.of(method), n));
            assertThrows(ArithmeticException.class, () -> after.run(Signatures.of(method), n));
        }
        assertEquals(before.run(Signatures.of(method), 1), after.run(Signatures.of(method), 1));
    }

    @Test public void specializesDispatcherWithLiveConstantInLoopHeader() throws Exception {
        Method method = shared(Opcode.ADD_INT_2ADDR, false, false, true);
        DexFile input = Fixtures.npDex(method);
        var result = transform(input, false);
        Method output = new DexContext(result.dex()).methods().get(Signatures.of(method));
        assertEquals(0, switches(output));
        for (int n : new int[]{Integer.MIN_VALUE, -1, 0, 1, Integer.MAX_VALUE}) {
            int left = n > 0 ? Integer.MAX_VALUE : Integer.MIN_VALUE;
            int right = n > 0 ? 100 : -100;
            int expected = (n > 0 ? (left + right) + left + right : (left + right) - left - right) + n + 12345;
            assertEquals(expected, new NpNumericInterpreter(input).run(Signatures.of(method), n));
            assertEquals(expected, new NpNumericInterpreter(result.dex()).run(Signatures.of(method), n));
        }
        Path path = directory.getRoot().toPath().resolve("header.dex");
        DexFiles.write(path, result.dex());
        assertEquals(0, transform(DexFiles.read(path), false).changedMethods());
    }

    private static void copy(MethodImplementationBuilder b, Opcode opcode, int to, int from) {
        if (opcode.format == org.jf.dexlib2.Format.Format12x) b.addInstruction(new BuilderInstruction12x(opcode, to, from));
        else if (opcode.format == org.jf.dexlib2.Format.Format22x) b.addInstruction(new BuilderInstruction22x(opcode, to, from));
        else b.addInstruction(new BuilderInstruction32x(opcode, to, from));
    }

    private Method copiedLoop(Opcode objectCopy, Opcode wideCopy) {
        return copiedLoop(objectCopy, wideCopy, false, false);
    }

    private Method copiedLoop(Opcode objectCopy, Opcode wideCopy, boolean shadowSelector, boolean overwriteAlias) {
        var b = new MethodImplementationBuilder(12);
        Fixtures.string(b, 1, "entry");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 1, 0, 0, 0, 0, Fixtures.NP_HASH));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        Fixtures.go(b, "header");
        b.addLabel("header");
        copy(b, objectCopy, 3, 8);
        copy(b, wideCopy, 5, 10);
        Fixtures.integer(b, 4, 12345);
        b.addInstruction(new BuilderInstruction31t(Opcode.SPARSE_SWITCH, 0, b.getLabel("payload")));
        // NP restores live aliases before the default backedge, too.
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 4, 9));
        if (shadowSelector) {
            b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 7, 0));
            b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 0, 8));
            if (overwriteAlias) b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 7, 9));
            b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 0, 7));
        }
        Fixtures.go(b, "header");
        b.addLabel("choose");
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ, 9, b.getLabel("negative")));
        Fixtures.integer(b, 0, 31); Fixtures.go(b, "header");
        b.addLabel("negative"); Fixtures.integer(b, 0, 77); Fixtures.go(b, "header");
        b.addLabel("done");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 3, 0, 0, 0, 0, Fixtures.HASH));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 2));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 2, 2, 0));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 2, 2, 4));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 2, 2, 9));
        b.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_LONG, 1, 2));
        b.addInstruction(new BuilderInstruction23x(Opcode.XOR_LONG, 1, 1, 5));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 1));
        b.addLabel("payload");
        b.addInstruction(new BuilderSparseSwitchPayload(List.of(new SwitchLabelElement(31, b.getLabel("done")),
            new SwitchLabelElement(77, b.getLabel("done")), new SwitchLabelElement("entry".hashCode(), b.getLabel("choose")))));
        return Fixtures.method("copiedLoop", List.of(new ImmutableMethodParameter("Ljava/lang/String;", Set.of(), "text"),
            new ImmutableMethodParameter("I", Set.of(), "input"), new ImmutableMethodParameter("J", Set.of(), "token")), "J", b.getMethodImplementation());
    }

    @Test public void preservesLiveObjectAndWideCopiesAcrossHeaderAndDefaultBackedge() throws Exception {
        List<Opcode> objects = List.of(Opcode.MOVE_OBJECT, Opcode.MOVE_OBJECT_FROM16, Opcode.MOVE_OBJECT_16);
        List<Opcode> wides = List.of(Opcode.MOVE_WIDE, Opcode.MOVE_WIDE_FROM16, Opcode.MOVE_WIDE_16);
        for (int encoding = 0; encoding < objects.size(); encoding++) {
            Method method = copiedLoop(objects.get(encoding), wides.get(encoding));
            DexFile input = Fixtures.npDex(method);
            var result = transform(input, false);
            assertEquals(0, switches(new DexContext(result.dex()).methods().get(Signatures.of(method))));
            var before = new NpNumericInterpreter(input);
            var after = new NpNumericInterpreter(result.dex());
            for (String text : List.of("", "中文😀")) for (int value : new int[]{Integer.MIN_VALUE, -1, 0, 1, Integer.MAX_VALUE})
                for (long token : new long[]{Long.MIN_VALUE, 0, Long.MAX_VALUE}) {
                    long expected = ((long)(text.hashCode() + (value <= 0 ? 77 : 31) + 12345 + value)) ^ token;
                    assertEquals(expected, before.run(Signatures.of(method), text, value, token));
                    assertEquals(expected, after.run(Signatures.of(method), text, value, token));
                }
            Path path = directory.getRoot().toPath().resolve("copies-" + encoding + ".dex");
            DexFiles.write(path, result.dex());
            assertEquals(0, transform(DexFiles.read(path), false).changedMethods());
        }
    }

    @Test public void provesSelectorRestoredAfterTemporaryObjectReuseButRejectsAnOverwrittenAlias() throws Exception {
        for (boolean overwrite : new boolean[]{false, true}) {
            Method method = copiedLoop(Opcode.MOVE_OBJECT_FROM16, Opcode.MOVE_WIDE_FROM16, true, overwrite);
            DexFile input = Fixtures.npDex(method);
            var pass = new DispatcherTransformer();
            var rawContext = new MethodContext(new DexContext(input), method);
            pass.prepare(rawContext.dex());
            int rawEdits = pass.run(rawContext).edits();
            if (overwrite) assertEquals(0, rawEdits); else assertTrue("Recognize the original shuffle before copy cleanup", rawEdits > 0);
            var result = transform(input, false);
            long remaining = switches(new DexContext(result.dex()).methods().get(Signatures.of(method)));
            if (overwrite) assertTrue(remaining > 0); else assertEquals(0, remaining);
            for (int value : new int[]{-1, 0, 1}) for (long token : new long[]{Long.MIN_VALUE, 0, Long.MAX_VALUE}) {
                long expected = ((long)("payload😀".hashCode() + (value <= 0 ? 77 : 31) + 12345 + value)) ^ token;
                assertEquals(expected, new NpNumericInterpreter(input).run(Signatures.of(method), "payload😀", value, token));
                assertEquals(expected, new NpNumericInterpreter(result.dex()).run(Signatures.of(method), "payload😀", value, token));
            }
            Path path = directory.getRoot().toPath().resolve("shadow-" + overwrite + ".dex");
            DexFiles.write(path, result.dex());
            assertEquals(0, transform(DexFiles.read(path), false).changedMethods());
        }
    }

    @Test public void updatedFixtureRestoresBusinessLoopsAndSwitches() throws Exception {
        DexFile input = DexFiles.read(Path.of(Objects.requireNonNull(getClass().getResource("/np-updated/full-planar.dex")).toURI()));
        var result = transform(input, true);
        var output = new DexContext(result.dex());
        String owner = "Ldev/deobfuscator/fixture/cases/FlowCases;->";
        for (String name : List.of("sign(I)I", "nested(II)I", "loop(I)I"))
            assertEquals(name, 0, switches(output.methods().get(owner + name)));
        for (String name : List.of("denseSwitch(I)I", "sparseSwitch(I)I")) {
            Set<Integer> businessKeys = name.startsWith("dense") ? Set.of(0, 1, 2, 3) : Set.of(-1000, 7, 100000);
            var graph = new CodeGraph(output.methods().get(owner + name).getImplementation());
            for (int i = 0; i < graph.size(); i++) if (CodeGraph.isSwitch(graph.at(i).getOpcode()))
                for (var element : graph.payload(i).getSwitchElements()) assertTrue(name, businessKeys.contains(element.getKey()));
        }
        var interpreter = new NpNumericInterpreter(result.dex());
        for (int n : new int[]{Integer.MIN_VALUE, -1, 0, 1, 2, 3, 8, 16, Integer.MAX_VALUE}) {
            int expectedLoop = 0;
            for (int index = 1; index < n && index <= 7; index += 2) expectedLoop += index;
            int expectedSwitch = n >= 0 && n <= 3 ? 11 * (n + 1) : -9;
            assertEquals(expectedLoop, interpreter.run(owner + "loop(I)I", n));
            assertEquals(expectedSwitch, interpreter.run(owner + "denseSwitch(I)I", n));
        }
        for (int n : new int[]{Integer.MIN_VALUE, -1000, -1, 0, 7, 100000, Integer.MAX_VALUE}) {
            int expected = n == -1000 ? 17 : n == 7 ? 31 : n == 100000 ? 99 : -1;
            assertEquals(expected, interpreter.run(owner + "sparseSwitch(I)I", n));
        }
    }
}
