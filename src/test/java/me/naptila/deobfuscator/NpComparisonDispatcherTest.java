package me.naptila.deobfuscator;

import java.nio.file.*;
import java.util.*;
import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import me.naptila.deobfuscator.transformers.np.controlflow.ComparisonDispatchers;
import me.naptila.deobfuscator.transformers.np.controlflow.FlowerTransformer;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.immutable.*;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class NpComparisonDispatcherTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    @Test public void hashDispatchAllowsInterveningLiveConstants() {
        String helper = "Lsample/Hash;";
        var ref = new org.jf.dexlib2.immutable.reference.ImmutableMethodReference(helper, "hash", List.of("Ljava/lang/Object;"), "I");
        var hashCode = new MethodImplementationBuilder(1);
        hashCode.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0,
                new org.jf.dexlib2.immutable.reference.ImmutableMethodReference("Ljava/lang/Object;", "hashCode", List.of(), "I")));
        hashCode.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        hashCode.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        var hash = new ImmutableMethod(helper, "hash", List.of(new ImmutableMethodParameter("Ljava/lang/Object;", Set.of(), null)),
                "I", 9, Set.of(), Set.of(), hashCode.getMethodImplementation());
        var b = new MethodImplementationBuilder(4);
        Fixtures.string(b, 0, "a"); Fixtures.go(b, "loop");
        b.addLabel("loop"); b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, ref));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 2));
        Fixtures.integer(b, 3, 47);
        b.addInstruction(new BuilderInstruction31t(Opcode.SPARSE_SWITCH, 2, b.getLabel("payload")));
        Fixtures.integer(b, 3, -1); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 3));
        b.addLabel("first"); Fixtures.string(b, 0, "b"); Fixtures.go(b, "loop");
        b.addLabel("second"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 3));
        b.addLabel("payload"); b.addInstruction(new BuilderSparseSwitchPayload(List.of(
                new SwitchLabelElement("a".hashCode(), b.getLabel("first")), new SwitchLabelElement("b".hashCode(), b.getLabel("second")))));
        Method method = Fixtures.method("hashStates", List.of(), "I", b.getMethodImplementation());
        var classes = new ArrayList<ClassDef>(Fixtures.dex(method).getClasses());
        classes.add(new ImmutableClassDef(helper, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(hash)));
        DexFile input = new ImmutableDexFile(Opcodes.forApi(28), classes);
        var result = transform(input, true);
        Method output = new DexContext(result.dex()).methods().get(Signatures.of(method));
        assertEquals(0, count(output, Opcode.SPARSE_SWITCH));
        assertEquals(47, new NpNumericInterpreter(input).run(Signatures.of(method)));
        assertEquals(47, new NpNumericInterpreter(result.dex()).run(Signatures.of(method)));
    }

    private DexEngine.Result transform(DexFile input, boolean full) {
        var specs = full ? RunConfiguration.defaults().transformers() : List.of(new TransformerSpec("np.flower"));
        var result = new Deobfuscator(TransformerRegistry.discover()).transform(input, specs, 20);
        assertEquals(result.methods().toString(), 0, result.failedMethods());
        assertTrue(result.methods().toString(), result.methods().stream().allMatch(DexEngine.MethodReport::converged));
        return result;
    }
    private long count(Method method, Opcode op) {
        long count = 0;
        for (var i : method.getImplementation().getInstructions()) if (i.getOpcode() == op) count++;
        return count;
    }
    private static void compare(MethodImplementationBuilder b, int key, String target, boolean reversed) {
        Fixtures.integer(b, 1, key);
        b.addInstruction(new BuilderInstruction22t(Opcode.IF_EQ, reversed ? 1 : 0, reversed ? 0 : 1, b.getLabel(target)));
    }
    private static void xor(MethodImplementationBuilder b, Opcode op, int key) {
        if (op == Opcode.XOR_INT_LIT16) b.addInstruction(new BuilderInstruction22s(op, 0, 0, key));
        else if (op == Opcode.XOR_INT_LIT8) b.addInstruction(new BuilderInstruction22b(op, 0, 0, key));
        else if (op == Opcode.XOR_INT_2ADDR) b.addInstruction(new BuilderInstruction12x(op, 0, 4));
        else b.addInstruction(new BuilderInstruction23x(op, 0, 0, 4));
    }
    private Method branching(Opcode xor, boolean reversed) {
        int key = xor == Opcode.XOR_INT_LIT8 ? 77 : 2345;
        var b = new MethodImplementationBuilder(6);
        Fixtures.integer(b, 4, key);
        Fixtures.integer(b, 0, 14 ^ key);
        Fixtures.go(b, "loop");
        b.addLabel("loop"); xor(b, xor, key);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("zero")));
        compare(b, 14, "entry", reversed);
        // This is deliberately written between comparisons and used after the dispatcher.
        Fixtures.integer(b, 3, 17);
        compare(b, 49, "negative", reversed);
        compare(b, 204, "positive", reversed);
        Fixtures.go(b, "loop");
        b.addLabel("entry");
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ, 5, b.getLabel("chooseNegative")));
        Fixtures.integer(b, 0, 204 ^ key); Fixtures.go(b, "loop");
        b.addLabel("chooseNegative"); Fixtures.integer(b, 0, 49 ^ key); Fixtures.go(b, "loop");
        b.addLabel("negative");
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 2, 3, 1));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 2, 2, 5));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
        b.addLabel("positive");
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 2, 3, 0));
        b.addInstruction(new BuilderInstruction23x(Opcode.SUB_INT, 2, 2, 5));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
        b.addLabel("zero"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 5));
        return Fixtures.method("branching", List.of(new ImmutableMethodParameter("I", Set.of(), "input")), "I", b.getMethodImplementation());
    }
    @Test public void restoresAllXorEncodingsAndPreservesLiveComparisonWrites() throws Exception {
        for (Opcode op : List.of(Opcode.XOR_INT, Opcode.XOR_INT_2ADDR, Opcode.XOR_INT_LIT8, Opcode.XOR_INT_LIT16)) {
            for (boolean reversed : List.of(false, true)) {
                Method method = branching(op, reversed);
                DexFile input = Fixtures.dex(method);
                var result = transform(input, true);
                Method output = Fixtures.first(result.dex());
                assertEquals(0, count(output, Opcode.IF_EQ));
                assertEquals(0, count(output, Opcode.IF_EQZ));
                assertEquals(0, count(output, op));
                assertEquals("Business condition must survive", 1, count(output, Opcode.IF_LEZ));
                var before = new NpNumericInterpreter(input);
                var after = new NpNumericInterpreter(result.dex());
                for (int n : new int[]{Integer.MIN_VALUE, -100, -1, 0, 1, 100, Integer.MAX_VALUE}) {
                    int expected = n <= 0 ? 17 + 49 + n : 17 + 204 - n;
                    assertEquals(expected, before.run(Signatures.of(method), n));
                    assertEquals(expected, after.run(Signatures.of(method), n));
                }
                Path path = directory.getRoot().toPath().resolve(op.name() + reversed + ".dex");
                DexFiles.write(path, result.dex());
                assertEquals(0, transform(DexFiles.read(path), true).changedMethods());
            }
        }
    }

    private Method unresolved(boolean unknown, boolean internalTarget, boolean hasXor) {
        var b = new MethodImplementationBuilder(3);
        if (unknown) b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 0, 2));
        else Fixtures.integer(b, 0, 1234); // neither iteration of XOR matches a case
        b.addLabel("loop");
        if (hasXor) xor(b, Opcode.XOR_INT_LIT16, 1633);
        compare(b, 14, internalTarget ? "inside" : "done", false);
        b.addLabel("inside"); compare(b, 49, "done", false);
        Fixtures.go(b, "loop");
        b.addLabel("done"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        return Fixtures.method("unresolved", List.of(new ImmutableMethodParameter("I", Set.of(), "input")), "I", b.getMethodImplementation());
    }
    @Test public void retainsUnknownStateLoopingDefaultAndNonDispatcherBranches() {
        for (Method method : List.of(unresolved(true, false, true), unresolved(false, false, true),
                unresolved(true, true, true), unresolved(true, false, false))) {
            assertEquals(0, transform(Fixtures.dex(method), false).changedMethods());
        }
    }

    @Test public void followsSplitComparisonsAndBackedgeThroughXorConstant() {
        var b = new MethodImplementationBuilder(3);
        Fixtures.integer(b, 0, 14 ^ 1234); Fixtures.go(b, "loop");
        b.addLabel("loop"); Fixtures.integer(b, 1, 1234);
        b.addInstruction(new BuilderInstruction12x(Opcode.XOR_INT_2ADDR, 0, 1));
        Fixtures.go(b, "compare");
        b.addLabel("yes"); b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 0, 1, 2));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("no"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
        b.addLabel("compare"); compare(b, 14, "yes", false); Fixtures.go(b, "second");
        b.addLabel("second"); compare(b, 49, "no", false); Fixtures.go(b, "loop");
        Method method = Fixtures.method("split", List.of(new ImmutableMethodParameter("I", Set.of(), "n")), "I", b.getMethodImplementation());
        var result = transform(Fixtures.dex(method), true);
        assertEquals(0, count(Fixtures.first(result.dex()), Opcode.IF_EQ));
        assertEquals(0, count(Fixtures.first(result.dex()), Opcode.XOR_INT_2ADDR));
        var interpreter = new NpNumericInterpreter(result.dex());
        for (int n : new int[]{-1, 0, 100}) assertEquals(n + 14, interpreter.run(Signatures.of(method), n));
    }

    private Method copiedState(Opcode move, boolean unknown, boolean looping) {
        return copiedState(move, false, unknown, looping);
    }

    private Method copiedState(Opcode move, boolean reversedXor, boolean unknown, boolean looping) {
        int state = move == Opcode.MOVE ? 3 : 16;
        int key = 1542302;
        var b = new MethodImplementationBuilder(20);
        if (unknown) b.addInstruction(new BuilderInstruction22x(Opcode.MOVE_FROM16, state, 19));
        else Fixtures.integer(b, state, looping ? 1234 : 19 ^ key);
        Fixtures.go(b, "loop");
        b.addLabel("loop"); Fixtures.integer(b, 17, key);
        b.addInstruction(new BuilderInstruction23x(Opcode.XOR_INT, 0, reversedXor ? 17 : state, reversedXor ? state : 17));
        Fixtures.go(b, "first");
        b.addLabel("negative"); Fixtures.integer(b, state, 76 ^ key); Fixtures.go(b, "loop");
        b.addLabel("positive"); Fixtures.integer(b, state, 50 ^ key); Fixtures.go(b, "loop");
        b.addLabel("choose");
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ, 19, b.getLabel("negative")));
        Fixtures.go(b, "positive");
        b.addLabel("first"); compare(b, 19, "choose", false); Fixtures.go(b, "second");
        b.addLabel("second"); compare(b, 50, "done", false); Fixtures.go(b, "third");
        b.addLabel("third"); compare(b, 76, "done", true);
        if (move == Opcode.MOVE) b.addInstruction(new BuilderInstruction12x(move, state, 0));
        else if (move == Opcode.MOVE_FROM16) b.addInstruction(new BuilderInstruction22x(move, state, 0));
        else b.addInstruction(new BuilderInstruction32x(move, state, 0));
        Fixtures.go(b, "loop");
        b.addLabel("done");
        // Both the encoded state and comparison constant remain observable after recovery.
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 2, state, 0));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 2, 2, 1));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 2, 2, 19));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
        return Fixtures.method("copiedState", List.of(new ImmutableMethodParameter("I", Set.of(), "n")), "I", b.getMethodImplementation());
    }

    @Test public void restoresSeparateSelectorWithStateCopyBackedge() throws Exception {
        for (Opcode move : List.of(Opcode.MOVE, Opcode.MOVE_FROM16, Opcode.MOVE_16)) {
            for (boolean reversedXor : List.of(false, true)) {
                Method method = copiedState(move, reversedXor, false, false);
                DexFile input = Fixtures.dex(method);
                var result = transform(input, true);
                Method output = Fixtures.first(result.dex());
                assertEquals(move.name, 0, count(output, Opcode.IF_EQ));
                assertEquals(move.name, 0, count(output, Opcode.XOR_INT));
                assertEquals(1, count(output, Opcode.IF_LEZ));
                var before = new NpNumericInterpreter(input);
                var after = new NpNumericInterpreter(result.dex());
                for (int n : new int[]{Integer.MIN_VALUE, -100, -1, 0, 1, 100, Integer.MAX_VALUE}) {
                    int selected = n <= 0 ? 76 : 50;
                    int expected = (selected ^ 1542302) + selected + selected + n;
                    assertEquals(expected, before.run(Signatures.of(method), n));
                    assertEquals(expected, after.run(Signatures.of(method), n));
                }
                Path path = directory.getRoot().toPath().resolve(move.name() + reversedXor + ".dex");
                DexFiles.write(path, result.dex());
                assertEquals(0, transform(DexFiles.read(path), true).changedMethods());
            }
        }
    }

    @Test public void retainsUnknownAndLoopingCopiedStates() {
        for (Opcode move : List.of(Opcode.MOVE, Opcode.MOVE_FROM16, Opcode.MOVE_16)) {
            for (Method method : List.of(copiedState(move, true, false), copiedState(move, false, true))) {
                Method output = Fixtures.first(transform(Fixtures.dex(method), false).dex());
                assertEquals(3, count(output, Opcode.IF_EQ));
                assertEquals(1, count(output, Opcode.XOR_INT));
            }
        }
    }

    private Method rotated(boolean unknown) {
        return rotated(unknown, false, Opcode.MOVE);
    }

    private Method rotated(boolean unknown, boolean twoAddress, Opcode copy) {
        var b = new MethodImplementationBuilder(5);
        Fixtures.integer(b, 1, 17); Fixtures.integer(b, 2, 54); Fixtures.integer(b, 3, 471);
        if (unknown) b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 0, 4));
        else Fixtures.integer(b, 0, 17);
        Fixtures.go(b, "first");
        b.addLabel("transition"); Fixtures.integer(b, 0, 54); Fixtures.go(b, "first");
        b.addLabel("second");
        b.addInstruction(new BuilderInstruction22t(Opcode.IF_EQ, 0, 2, b.getLabel("setLast")));
        b.addInstruction(new BuilderInstruction22t(Opcode.IF_EQ, 0, 3, b.getLabel("done")));
        if (copy == Opcode.MOVE) b.addInstruction(new BuilderInstruction12x(copy, 2, 0));
        else if (copy == Opcode.MOVE_FROM16) b.addInstruction(new BuilderInstruction22x(copy, 2, 0));
        else b.addInstruction(new BuilderInstruction32x(copy, 2, 0));
        Fixtures.integer(b, 0, 1757);
        b.addLabel("xor"); b.addInstruction(twoAddress ? new BuilderInstruction12x(Opcode.XOR_INT_2ADDR, 0, 2)
                : new BuilderInstruction23x(Opcode.XOR_INT, 0, 2, 0));
        b.addLabel("first");
        b.addInstruction(new BuilderInstruction22t(Opcode.IF_EQ, 0, 1, b.getLabel("transition")));
        Fixtures.go(b, "second");
        b.addLabel("setLast");
        Fixtures.integer(b, 0, 471);
        Fixtures.go(b, "first");
        b.addLabel("done");
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 0, 0, 4));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        return Fixtures.method("rotated", List.of(new ImmutableMethodParameter("I", Set.of(), "input")), "I", b.getMethodImplementation());
    }

    @Test public void restoresRotatedDefaultXorReachedByFallthrough() throws Exception {
        Method method = rotated(false);
        DexFile input = Fixtures.dex(method);
        var result = transform(input, true);
        Method output = Fixtures.first(result.dex());
        assertEquals(0, count(output, Opcode.IF_EQ));
        assertEquals(0, count(output, Opcode.XOR_INT));
        for (int n : new int[]{Integer.MIN_VALUE, -10, 0, 1, Integer.MAX_VALUE}) {
            assertEquals(471 + n, new NpNumericInterpreter(input).run(Signatures.of(method), n));
            assertEquals(471 + n, new NpNumericInterpreter(result.dex()).run(Signatures.of(method), n));
        }
        Path file = directory.getRoot().toPath().resolve("rotated.dex");
        DexFiles.write(file, result.dex());
        assertEquals(0, transform(DexFiles.read(file), true).changedMethods());
    }

    @Test public void retainsUnprovenRotatedState() {
        for (boolean twoAddress : new boolean[]{false, true}) {
            Method method = rotated(true, twoAddress, Opcode.MOVE);
            var result = transform(Fixtures.dex(method), false);
            Method output = Fixtures.first(result.dex());
            assertTrue(count(output, Opcode.IF_EQ) > 0);
            assertEquals(1, count(output, twoAddress ? Opcode.XOR_INT_2ADDR : Opcode.XOR_INT));
            for (int n : new int[]{17, 54})
                assertEquals(new NpNumericInterpreter(Fixtures.dex(method)).run(Signatures.of(method), n),
                        new NpNumericInterpreter(result.dex()).run(Signatures.of(method), n));
        }
    }

    @Test public void restoresTwoAddressXorWithSelectorCopiedIntoOtherOperand() throws Exception {
        for (Opcode copy : List.of(Opcode.MOVE, Opcode.MOVE_FROM16, Opcode.MOVE_16)) {
            Method method = rotated(false, true, copy); DexFile input = Fixtures.dex(method);
            var result = transform(input, true); Method output = Fixtures.first(result.dex());
            assertEquals(copy.name, 0, count(output, Opcode.IF_EQ));
            assertEquals(copy.name, 0, count(output, Opcode.XOR_INT_2ADDR));
            for (int n : new int[]{Integer.MIN_VALUE, -100, -1, 0, 1, 100, Integer.MAX_VALUE}) {
                assertEquals(471 + n, new NpNumericInterpreter(input).run(Signatures.of(method), n));
                assertEquals(471 + n, new NpNumericInterpreter(result.dex()).run(Signatures.of(method), n));
            }
            Path file = directory.getRoot().toPath().resolve("two-address-" + copy.name() + ".dex"); DexFiles.write(file, result.dex());
            assertEquals(0, transform(DexFiles.read(file), true).changedMethods());
        }
    }

    private static void shufflePayload(MethodImplementationBuilder b) {
        for (int copy = 0; copy < 8; copy++) {
            b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_OBJECT_16, 16, 20));
            b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_WIDE_16, 18, 22));
        }
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_WIDE_16, 14, 892));
    }

    private Method mixedCopies() {
        var b = new MethodImplementationBuilder(24); Fixtures.integer(b, 0, 19); Fixtures.go(b, "first");
        b.addLabel("xor"); b.addInstruction(new BuilderInstruction12x(Opcode.XOR_INT_2ADDR, 0, 1));
        b.addLabel("first"); shufflePayload(b); compare(b, 19, "choose", false);
        shufflePayload(b); compare(b, 50, "done", false);
        shufflePayload(b); compare(b, 76, "done", true);
        shufflePayload(b); compare(b, 123, "done", false);
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 1, 0)); Fixtures.integer(b, 0, 1757); Fixtures.go(b, "xor");
        b.addLabel("choose"); b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ, 21, b.getLabel("negative")));
        Fixtures.integer(b, 1, 50 ^ 1757); Fixtures.integer(b, 0, 1757); Fixtures.go(b, "xor");
        b.addLabel("negative"); Fixtures.integer(b, 1, 123 ^ 1757); Fixtures.integer(b, 0, 1757); Fixtures.go(b, "xor");
        b.addLabel("done"); b.addInstruction(new BuilderInstruction22x(Opcode.MOVE_OBJECT_FROM16, 4, 16));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 4, 0, 0, 0, 0, Fixtures.HASH));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 3));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 5, 0, 1));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 5, 5, 21));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 5, 5, 3));
        b.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_LONG, 6, 5));
        b.addInstruction(new BuilderInstruction23x(Opcode.XOR_LONG, 6, 6, 18));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 6));
        return Fixtures.method("mixedCopies", List.of(new ImmutableMethodParameter("Ljava/lang/String;", Set.of(), "text"),
                new ImmutableMethodParameter("I", Set.of(), "input"), new ImmutableMethodParameter("J", Set.of(), "token")), "J", b.getMethodImplementation());
    }

    @Test public void longComparisonPrefixesPreserveUnknownObjectAndWidePayloads() throws Exception {
        Method method = mixedCopies(); DexFile input = Fixtures.dex(method);
        var pass = new FlowerTransformer();
        var context = new MethodContext(new DexContext(input), method); pass.prepare(context.dex());
        assertTrue("The original long prefix must be recognized before cleanup", pass.run(context).edits() > 0);
        var result = transform(input, true); Method output = Fixtures.first(result.dex());
        assertEquals(0, count(output, Opcode.IF_EQ)); assertEquals(0, count(output, Opcode.XOR_INT_2ADDR));
        assertEquals("Business predicate survives", 1, count(output, Opcode.IF_LEZ));
        var before = new NpNumericInterpreter(input); var after = new NpNumericInterpreter(result.dex());
        for (String text : List.of("", "payload", "中文😀")) for (int n : new int[]{Integer.MIN_VALUE, -1, 0, 1, Integer.MAX_VALUE})
            for (long token : new long[]{Long.MIN_VALUE, -1, 0, 1, 0x1234567887654321L, Long.MAX_VALUE}) {
                int selected = n <= 0 ? 123 : 50;
                long expected = ((long)(selected + selected + n + text.hashCode())) ^ token;
                assertEquals(expected, before.run(Signatures.of(method), text, n, token));
                assertEquals(expected, after.run(Signatures.of(method), text, n, token));
            }
        Path file = directory.getRoot().toPath().resolve("mixed-copies.dex"); DexFiles.write(file, result.dex());
        assertEquals(0, transform(DexFiles.read(file), true).changedMethods());
    }

    private static void integerCopy(MethodImplementationBuilder b, Opcode op, int target, int source) {
        if (op == Opcode.MOVE) b.addInstruction(new BuilderInstruction12x(op, target, source));
        else if (op == Opcode.MOVE_FROM16) b.addInstruction(new BuilderInstruction22x(op, target, source));
        else b.addInstruction(new BuilderInstruction32x(op, target, source));
    }

    private Method copiedComparisons(Opcode copy, boolean unknown, boolean overwriteAlias) {
        int alias = copy == Opcode.MOVE ? 5 : 16;
        var b = new MethodImplementationBuilder(24);
        if (unknown) integerCopy(b, Opcode.MOVE_FROM16, 0, 21);
        else Fixtures.integer(b, 0, 17);
        Fixtures.go(b, "first");
        b.addLabel("xor"); Fixtures.integer(b, 3, 1757);
        b.addInstruction(new BuilderInstruction23x(Opcode.XOR_INT, 0, 2, 3));
        b.addLabel("first"); compare(b, 17, "choose", false);
        b.addInstruction(new BuilderInstruction22x(Opcode.MOVE_OBJECT_FROM16, 4, 20));
        integerCopy(b, copy, alias, 0);
        if (overwriteAlias) integerCopy(b, Opcode.MOVE_FROM16, alias, 21);
        integerCopy(b, copy, 5, alias);
        Fixtures.integer(b, 1, 54);
        b.addInstruction(new BuilderInstruction22t(Opcode.IF_EQ, 1, 5, b.getLabel("negative")));
        integerCopy(b, copy, 0, alias);
        Fixtures.integer(b, 1, 471);
        b.addInstruction(new BuilderInstruction22t(Opcode.IF_EQ, 5, 1, b.getLabel("sixteen")));
        integerCopy(b, copy, 0, alias);
        compare(b, 500, "thirtyTwo", false);
        integerCopy(b, copy, 2, alias); Fixtures.go(b, "xor");
        b.addLabel("choose");
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ, 21, b.getLabel("negative")));
        Fixtures.integer(b, 2, 1833); Fixtures.go(b, "xor");
        b.addLabel("negative"); Fixtures.integer(b, 2, 1802); Fixtures.go(b, "xor");
        b.addLabel("thirtyTwo"); Fixtures.integer(b, 1, 32); Fixtures.go(b, "done");
        b.addLabel("sixteen"); Fixtures.integer(b, 1, 16);
        b.addLabel("done");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 4, 0, 0, 0, 0, Fixtures.HASH));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 3));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 3, 3, alias));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 3, 3, 1));
        b.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_LONG, 6, 3));
        b.addInstruction(new BuilderInstruction23x(Opcode.XOR_LONG, 6, 6, 22));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 6));
        return Fixtures.method("copiedComparisons", List.of(new ImmutableMethodParameter("Ljava/lang/String;", Set.of(), "text"),
                new ImmutableMethodParameter("I", Set.of(), "input"), new ImmutableMethodParameter("J", Set.of(), "token")), "J", b.getMethodImplementation());
    }

    @Test public void followsSelectorCopiesBetweenComparisonsAndBackToSelector() throws Exception {
        for (Opcode copy : List.of(Opcode.MOVE, Opcode.MOVE_FROM16, Opcode.MOVE_16)) {
            Method method = copiedComparisons(copy, false, false); DexFile input = Fixtures.dex(method);
            var result = transform(input, true); Method output = Fixtures.first(result.dex());
            assertEquals(copy.name, 0, count(output, Opcode.IF_EQ));
            assertEquals(copy.name, 0, count(output, Opcode.XOR_INT));
            assertEquals("Business condition survives", 1, count(output, Opcode.IF_LEZ));
            var before = new NpNumericInterpreter(input); var after = new NpNumericInterpreter(result.dex());
            for (String text : List.of("", "payload", "中文😀"))
                for (int n : new int[]{Integer.MIN_VALUE, -1, 0, 1, Integer.MAX_VALUE})
                    for (long token : new long[]{Long.MIN_VALUE, 0, 0x1234567887654321L, Long.MAX_VALUE}) {
                        long expected = ((long)(text.hashCode() + (n <= 0 ? 471 + 16 : 500 + 32))) ^ token;
                        assertEquals(expected, before.run(Signatures.of(method), text, n, token));
                        assertEquals(expected, after.run(Signatures.of(method), text, n, token));
                    }
            Path file = directory.getRoot().toPath().resolve("copied-comparisons-" + copy.name() + ".dex");
            DexFiles.write(file, result.dex());
            assertEquals(0, transform(DexFiles.read(file), true).changedMethods());
        }
    }

    @Test public void retainsUnknownStateAndStopsFollowingOverwrittenSelectorCopies() {
        for (Opcode copy : List.of(Opcode.MOVE, Opcode.MOVE_FROM16, Opcode.MOVE_16)) {
            Method method = copiedComparisons(copy, true, false);
            var result = transform(Fixtures.dex(method), false);
            assertTrue(count(Fixtures.first(result.dex()), Opcode.IF_EQ) > 0);
            assertTrue(count(Fixtures.first(result.dex()), Opcode.XOR_INT) > 0);
            var before = new NpNumericInterpreter(Fixtures.dex(method)); var after = new NpNumericInterpreter(result.dex());
            for (int state : new int[]{17, 54, 471, 500})
                assertEquals(before.run(Signatures.of(method), "payload", state, 123L),
                        after.run(Signatures.of(method), "payload", state, 123L));
            method = copiedComparisons(copy, false, true);
            assertTrue(ComparisonDispatchers.find(
                    new CodeGraph(method.getImplementation())).isEmpty());
            assertEquals(0, transform(Fixtures.dex(method), false).changedMethods());
        }
    }

    @Test public void restoresD8DebugAndReleaseSynchronizedMethod() throws Exception {
        for (String mode : List.of("debug", "release")) {
            DexFile input = DexFiles.read(Path.of(Objects.requireNonNull(getClass().getResource("/np-comparison/" + mode + ".dex")).toURI()));
            var result = transform(input, true);
            Method method = Fixtures.first(result.dex());
            assertEquals(0, count(method, Opcode.XOR_INT_LIT16));
            assertEquals(0, count(method, Opcode.SPARSE_SWITCH));
            assertEquals(0, count(method, Opcode.IF_EQ));
            assertEquals(1, count(method, Opcode.MONITOR_ENTER));
            assertEquals(2, count(method, Opcode.MONITOR_EXIT));
            assertEquals(1, count(method, Opcode.THROW));
            assertEquals(1, count(method, Opcode.IF_LE));
            assertFalse(method.getImplementation().getTryBlocks().isEmpty());
            var graph = new CodeGraph(method.getImplementation());
            for (int i = 0; i < graph.size(); i++) if (graph.at(i).getOpcode() == Opcode.MONITOR_EXIT)
                assertEquals("Both exits must keep their catch-all", 1, graph.protection(i).size());
            Path path = directory.getRoot().toPath().resolve(mode + ".dex");
            DexFiles.write(path, result.dex());
            assertEquals(0, transform(DexFiles.read(path), true).changedMethods());
        }
    }
}
