package me.naptila.deobfuscator;

import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.ConstantAnalysis;
import me.naptila.deobfuscator.dex.WideConstantAnalysis;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class WideConstantAnalysisTest {
    private WideConstantAnalysis analyze(MethodImplementationBuilder b) {
        CodeGraph graph = new CodeGraph(b.getMethodImplementation());
        return new WideConstantAnalysis(graph, new ConstantAnalysis(graph));
    }
    @Test public void signExtensionAndWideXorMatchJavaForBoundaryAndRandomBits() {
        Random random = new Random(0x4e503830L);
        int[] edges = {Integer.MIN_VALUE, Integer.MAX_VALUE, -1, 0, 1};
        for (int n = 0; n < 128; n++) {
            int key = n < edges.length ? edges[n] : random.nextInt(); long encoded = random.nextLong();
            var b = new MethodImplementationBuilder(7);
            Fixtures.integer(b, 0, key);
            b.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_LONG, 1, 0));
            b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 3, encoded));
            b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_WIDE_16, 5, 3));
            b.addInstruction(new BuilderInstruction12x(Opcode.XOR_LONG_2ADDR, 1, 5));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 1));
            var facts = analyze(b);
            assertEquals(Long.valueOf(key), facts.valueAt(1));
            assertEquals(Long.valueOf(encoded ^ (long)key), facts.valueAt(4));
        }
    }
    @Test public void clobberingEitherHalfInvalidatesTheWholeWideValue() {
        for (int word : new int[]{0, 1}) {
            var b = new MethodImplementationBuilder(4);
            b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 0, 123));
            Fixtures.integer(b, word, 7);
            b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 2, 456));
            b.addInstruction(new BuilderInstruction12x(Opcode.XOR_LONG_2ADDR, 0, 2));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
            assertNull(analyze(b).valueAt(3));
        }
    }
    @Test public void disagreeingPathsDoNotInventConstants() {
        var b = new MethodImplementationBuilder(5);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 4, b.getLabel("other")));
        b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 0, 7)); Fixtures.go(b, "join");
        b.addLabel("other"); b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 0, 8));
        b.addLabel("join"); b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 2, 9));
        b.addInstruction(new BuilderInstruction12x(Opcode.XOR_LONG_2ADDR, 0, 2));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
        assertNull(analyze(b).valueAt(5));
    }
    @Test public void handlerFactsUsePreThrowValuesAndInvalidateThrowingDestinations() {
        var b = new MethodImplementationBuilder(6);
        b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 0, 7));
        b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 2, 9)); Fixtures.integer(b, 5, 0);
        b.addLabel("start"); b.addInstruction(new BuilderInstruction23x(Opcode.DIV_INT, 1, 5, 5));
        b.addLabel("end"); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 4));
        b.addInstruction(new BuilderInstruction12x(Opcode.XOR_LONG_2ADDR, 0, 2));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_WIDE, 0, 2));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        b.addCatch(b.getLabel("start"), b.getLabel("end"), b.getLabel("handler"));
        var facts = analyze(b); assertNull(facts.valueAt(6)); assertEquals(Long.valueOf(9), facts.valueAt(7));
    }
}
