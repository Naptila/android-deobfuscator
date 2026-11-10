package me.naptila.deobfuscator;

import java.nio.file.*;
import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.Edits;
import me.naptila.deobfuscator.dex.MethodContext;
import me.naptila.deobfuscator.dex.Signatures;
import me.naptila.deobfuscator.io.DexFiles;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.immutable.ImmutableMethodParameter;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class BranchRelaxationTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    static Method forward() {
        var b = new MethodImplementationBuilder(2);
        b.addLabel("start");
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 1, b.getLabel("far")));
        b.addLabel("end");
        Fixtures.integer(b, 0, 10); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        for (int i = 0; i < 32740; i++) b.addInstruction(new BuilderInstruction10x(Opcode.NOP));
        b.addLabel("far"); Fixtures.integer(b, 0, 20); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.THROW, 0));
        b.addCatch(b.getLabel("start"), b.getLabel("end"), b.getLabel("handler"));
        return Fixtures.method("wide", List.of(new ImmutableMethodParameter("I", Set.of(), "input")), "I", b.getMethodImplementation());
    }
    static Method expanded() {
        var context = new MethodContext(forward());
        List<BuilderInstruction> padding = new ArrayList<>();
        for (int i = 0; i < 100; i++) padding.add(new BuilderInstruction10x(Opcode.NOP));
        Edits.apply(context.code(), List.of(new Edits.Edit(3, true, padding)));
        return context.finish();
    }
    @Test public void distantConditionalRoundTripsAndPreservesArmsAndProtection() throws Exception {
        Method output = expanded(); CodeGraph graph = new CodeGraph(output.getImplementation());
        assertEquals(Opcode.IF_NEZ, graph.at(0).getOpcode());
        assertEquals(Opcode.GOTO_32, graph.at(1).getOpcode());
        assertEquals(2, (int)graph.successors(0).get(0));
        assertEquals(graph.protection(0), graph.protection(1)); assertFalse(graph.protection(0).isEmpty());
        Path file = directory.getRoot().toPath().resolve("wide.dex"); DexFiles.write(file, Fixtures.dex(output));
        var interpreter = new NpNumericInterpreter(DexFiles.read(file));
        assertEquals(20, interpreter.run(Signatures.of(output), 0));
        assertEquals(10, interpreter.run(Signatures.of(output), -1));
        assertEquals(10, interpreter.run(Signatures.of(output), 1));
    }
    @Test public void backwardTwoRegisterConditionalIsWidened() {
        var b = new MethodImplementationBuilder(2); b.addLabel("start");
        for (int i = 0; i < 32740; i++) b.addInstruction(new BuilderInstruction10x(Opcode.NOP));
        b.addInstruction(new BuilderInstruction22t(Opcode.IF_LT, 0, 1, b.getLabel("start")));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        var c = new MethodContext(Fixtures.method("back", List.of(), "V", b.getMethodImplementation()));
        for (int i = 0; i < 100; i++) c.code().addInstruction(1, new BuilderInstruction10x(Opcode.NOP));
        var g = c.graph();
        assertEquals(Opcode.IF_GE, g.at(g.size() - 3).getOpcode());
        assertEquals(Opcode.GOTO_32, g.at(g.size() - 2).getOpcode());
        assertEquals(0, (int)g.successors(g.size() - 2).get(0));
    }
    public static void main(String[] args) throws Exception { DexFiles.write(Path.of(args[0]), Fixtures.dex(expanded())); }
}
