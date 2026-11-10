package me.naptila.deobfuscator;

import java.nio.file.Path;
import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.BranchThreading;
import me.naptila.deobfuscator.dex.MethodContext;
import me.naptila.deobfuscator.dex.SwitchDefaults;
import me.naptila.deobfuscator.io.DexFiles;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.immutable.ImmutableMethodParameter;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class ControlFlowCleanupTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    private Method sharedDefault(String mode) {
        MethodImplementationBuilder b = new MethodImplementationBuilder(4);
        if (mode.equals("read")) Fixtures.integer(b, 0, 90);
        if (mode.equals("bypass")) b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ, 3, b.getLabel("default")));
        b.addLabel("switch");
        b.addInstruction(new BuilderInstruction31t(Opcode.SPARSE_SWITCH, 3, b.getLabel("payload")));
        Fixtures.go(b, "default");
        b.addLabel("positive");
        if (mode.equals("read")) b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 1, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ, 3, b.getLabel("default")));
        Fixtures.integer(b, 0, 7); Fixtures.go(b, "return");
        b.addLabel("negative");
        if (mode.equals("write")) Fixtures.integer(b, 0, 9);
        Fixtures.go(b, "default");
        b.addLabel("default"); Fixtures.integer(b, 0, -1); Fixtures.go(b, "return");
        b.addLabel("return"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("payload");
        b.addInstruction(new BuilderSparseSwitchPayload(List.of(new SwitchLabelElement(-1, b.getLabel("negative")),
                new SwitchLabelElement(1, b.getLabel("positive")))));
        return Fixtures.method("sharedDefault", List.of(new ImmutableMethodParameter("I", Set.of(), "input")), "I", b.getMethodImplementation());
    }
    @Test public void normalizesSharedDefaultWithoutChangingAnyBranchAndReloads() throws Exception {
        Method original = sharedDefault("safe");
        MethodContext context = new MethodContext(original);
        assertEquals(1, SwitchDefaults.run(context));
        assertEquals(0, SwitchDefaults.run(context));
        Path path = directory.getRoot().toPath().resolve("default.dex");
        org.jf.dexlib2.writer.pool.DexPool.writeTo(path.toString(), Fixtures.dex(context.finish()));
        Method reloaded = Fixtures.first(DexFiles.read(path));
        for (int value : new int[]{Integer.MIN_VALUE, -1, 0, 1, 2, Integer.MAX_VALUE})
            assertEquals(Fixtures.execute(original, value), Fixtures.execute(reloaded, value));
    }
    @Test public void retainsDefaultWhenOldValueIsReadWrittenOrHeaderIsBypassed() {
        for (String mode : List.of("read", "write", "bypass"))
            assertEquals(mode, 0, SwitchDefaults.run(new MethodContext(sharedDefault(mode))));
    }
    @Test public void threadsSwitchEdgesAndSharedReturnsWithoutChangingResults() {
        Method original = sharedDefault("safe");
        MethodContext context = new MethodContext(original);
        assertTrue(BranchThreading.run(context) > 0);
        assertEquals(0, BranchThreading.run(context));
        for (int value : new int[]{-2, -1, 0, 1, 2})
            assertEquals(Fixtures.execute(original, value), Fixtures.execute(context.finish(), value));
    }
    @Test public void retainsGotoCycle() {
        MethodImplementationBuilder b = new MethodImplementationBuilder(0);
        b.addLabel("one"); Fixtures.go(b, "two");
        b.addLabel("two"); Fixtures.go(b, "one");
        MethodContext context = new MethodContext(Fixtures.method("cycle", List.of(), "V", b.getMethodImplementation()));
        assertEquals(0, BranchThreading.run(context));
    }
}
