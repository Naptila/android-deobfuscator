package me.naptila.deobfuscator;

import java.nio.file.Path;
import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.immutable.ImmutableMethodParameter;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class SwitchDefaultEdgesTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    private Method fixture(Opcode condition, boolean protectedCode) {
        var b = new MethodImplementationBuilder(4);
        Fixtures.integer(b, 0, 91); Fixtures.integer(b, 1, 0);
        b.addInstruction(new BuilderInstruction31t(Opcode.SPARSE_SWITCH, 3, b.getLabel("hash")));
        Fixtures.go(b, "default");
        b.addLabel("default"); Fixtures.integer(b, 0, -1); Fixtures.go(b, "select");
        b.addLabel("case");
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 2, 0)); // Old discriminator register is live.
        if (condition.name.endsWith("z")) b.addInstruction(new BuilderInstruction21t(condition, 3, b.getLabel("default")));
        else b.addInstruction(new BuilderInstruction22t(condition, 3, 1, b.getLabel("default")));
        Fixtures.integer(b, 0, 7); Fixtures.go(b, "select");
        b.addLabel("select");
        b.addInstruction(new BuilderInstruction31t(Opcode.PACKED_SWITCH, 0, b.getLabel("selector")));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("matched"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
        if (protectedCode) {
            b.addLabel("catch"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
            Fixtures.integer(b, 0, -9); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
            b.addCatch(b.getLabel("case"), b.getLabel("select"), b.getLabel("catch"));
        }
        b.addLabel("hash");
        b.addInstruction(new BuilderSparseSwitchPayload(List.of(new SwitchLabelElement(-1, b.getLabel("case")),
                new SwitchLabelElement(0, b.getLabel("case")), new SwitchLabelElement(1, b.getLabel("case")))));
        b.addLabel("selector"); b.addInstruction(new BuilderPackedSwitchPayload(7, List.of(b.getLabel("matched"))));
        return Fixtures.method("classify", List.of(new ImmutableMethodParameter("I", Set.of(), "key")), "I", b.getMethodImplementation());
    }
    @Test public void preservesBothEdgesForEveryConditionAndLiveOldDiscriminator() throws Exception {
        for (Opcode op : List.of(Opcode.IF_EQ, Opcode.IF_NE, Opcode.IF_LT, Opcode.IF_GE, Opcode.IF_LE, Opcode.IF_GT,
                Opcode.IF_EQZ, Opcode.IF_NEZ, Opcode.IF_LTZ, Opcode.IF_GEZ, Opcode.IF_LEZ, Opcode.IF_GTZ)) {
            Method before = fixture(op, false); var context = new MethodContext(before);
            assertEquals("Hoisting would overwrite a live input", 0, SwitchDefaults.run(context));
            assertEquals(op.name, 1, SwitchDefaultEdges.run(context));
            assertEquals("Splitting must converge", 0, SwitchDefaultEdges.run(context));
            Path path = directory.getRoot().toPath().resolve(op.toString() + ".dex");
            DexFiles.write(path, Fixtures.dex(context.finish()));
            var original = new NpNumericInterpreter(Fixtures.dex(before));
            var output = new NpNumericInterpreter(DexFiles.read(path));
            for (int value : new int[]{Integer.MIN_VALUE, -2, -1, 0, 1, 2, Integer.MAX_VALUE})
                assertEquals(op.name + " " + value, original.run(Signatures.of(before), value), output.run(Signatures.of(before), value));
        }
    }
    @Test public void retainsProtectedMethod() {
        assertEquals(0, SwitchDefaultEdges.run(new MethodContext(fixture(Opcode.IF_EQZ, true))));
    }
    @Test public void removesGotoToNextWithoutDroppingItsIncomingLabels() throws Exception {
        var b = new MethodImplementationBuilder(2);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ, 1, b.getLabel("jump")));
        Fixtures.integer(b, 0, 8);
        b.addLabel("jump"); Fixtures.go(b, "next");
        b.addLabel("next"); Fixtures.integer(b, 0, 7); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        Method method = Fixtures.method("next", List.of(new ImmutableMethodParameter("I", Set.of(), "key")), "I", b.getMethodImplementation());
        var context = new MethodContext(method);
        assertTrue(BranchThreading.run(context) > 0);
        assertEquals(0, BranchThreading.run(context));
        Path path = directory.getRoot().toPath().resolve("next.dex"); DexFiles.write(path, Fixtures.dex(context.finish()));
        var output = new NpNumericInterpreter(DexFiles.read(path));
        for (int value : new int[]{-1, 0, 1}) assertEquals(7, output.run(Signatures.of(method), value));
    }
}
