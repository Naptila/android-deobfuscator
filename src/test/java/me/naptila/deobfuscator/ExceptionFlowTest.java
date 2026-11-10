package me.naptila.deobfuscator;

import java.nio.file.*;
import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.DexEngine;
import me.naptila.deobfuscator.io.DexFiles;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class ExceptionFlowTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    private static DexFile input, output;
    @BeforeClass public static void transform() throws Exception {
        input = ExceptionFixtures.input(); var result = ExceptionFixtures.transform(input);
        assertEquals(result.methods().toString(), 0, result.failedMethods());
        assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged));
        output = result.dex();
    }
    private Method method(DexFile dex, String name) {
        return new DexContext(dex).methods().values().stream()
                .filter(m -> m.getDefiningClass().equals(ExceptionFixtures.OWNER) && m.getName().equals(name)).findFirst().orElseThrow();
    }
    private long count(Method method, Opcode opcode) {
        long n = 0;
        for (Instruction i : method.getImplementation().getInstructions()) if (i.getOpcode() == opcode) n++;
        return n;
    }
    private List<String> handlers(Method method, String invokedName) {
        CodeGraph graph = new CodeGraph(method.getImplementation());
        for (int i = 0; i < graph.size(); i++) if (graph.at(i) instanceof ReferenceInstruction r
                && r.getReference() instanceof MethodReference m && m.getName().equals(invokedName))
            return graph.protection(i).stream().map(CodeGraph.Handler::type).toList();
        throw new AssertionError("Missing invocation " + invokedName);
    }
    @Test public void exceptionOnlyRegisterValuesAndPreThrowDestinationRemainLive() {
        Method wide = method(output, "wideOnThrow"), destination = method(output, "destinationOnThrow");
        assertEquals(1, count(wide, Opcode.CONST_WIDE));
        assertEquals(1, count(wide, Opcode.DIV_INT));
        assertEquals(1, count(destination, Opcode.DIV_INT));
        boolean retained = false;
        for (Instruction i : destination.getImplementation().getInstructions())
            if (i instanceof NarrowLiteralInstruction n && n.getNarrowLiteral() == 42) retained = true;
        assertTrue(retained);
    }
    @Test public void unknownCallsAndOrderedTypedCatchAndCatchAllSurvive() {
        var expected = Arrays.asList("Ljava/lang/ArithmeticException;", "Ljava/lang/RuntimeException;", null);
        assertEquals(expected, handlers(method(input, "orderedCatch"), "raise"));
        assertEquals(expected, handlers(method(output, "orderedCatch"), "raise"));
        assertEquals(3, count(method(output, "orderedCatch"), Opcode.MOVE_EXCEPTION));
        assertEquals(Arrays.asList("Ljava/lang/ArithmeticException;", null), handlers(method(output, "nestedFinally"), "raise"));
        assertEquals(1, count(method(output, "nestedFinally"), Opcode.THROW));
        assertEquals(2, count(method(output, "nestedFinally"), Opcode.MOVE_EXCEPTION));
    }
    @Test public void removesUnreachableTryAndOrphanHandlerTogether() {
        Method cleaned = method(output, "deadTry");
        assertTrue(cleaned.getImplementation().getTryBlocks().isEmpty());
        assertEquals(0, count(cleaned, Opcode.MOVE_EXCEPTION));
        assertEquals(0, count(cleaned, Opcode.INVOKE_STATIC));
    }
    @Test public void specializesInsideSameProtectionAndRetainsLiveCrossBoundaryCalls() {
        assertEquals(0, count(method(output, "sharedSame"), Opcode.SPARSE_SWITCH));
        assertEquals(1, count(method(output, "sharedCross"), Opcode.SPARSE_SWITCH));
        assertEquals(0, count(method(output, "sharedSame"), Opcode.INVOKE_STATIC)); // Known strings; no initializer or live result.
        CodeGraph graph = new CodeGraph(method(output, "sharedCross").getImplementation());
        int invokes = 0;
        for (int i = 0; i < graph.size(); i++) if (graph.at(i).getOpcode() == Opcode.INVOKE_STATIC) {
            invokes++;
            assertEquals(List.of("Ljava/lang/RuntimeException;"), graph.protection(i).stream().map(CodeGraph.Handler::type).toList());
        }
        assertTrue(invokes > 0);
    }
    @Test public void protectedNullHashMustStillThrowIntoItsHandler() {
        Method cleaned = method(output, "protectedNullHash");
        assertEquals(1, count(cleaned, Opcode.INVOKE_STATIC));
        assertEquals(1, count(cleaned, Opcode.MOVE_EXCEPTION));
        assertEquals("Ljava/lang/NullPointerException;", cleaned.getImplementation().getTryBlocks().get(0).getExceptionHandlers().get(0).getExceptionType());
    }
    @Test public void exceptionTablesReloadAndTransformationIsIdempotent() throws Exception {
        Path path = directory.getRoot().toPath().resolve("exceptions.dex");
        DexFiles.write(path, output);
        DexFile reread = DexFiles.read(path);
        var again = ExceptionFixtures.transform(reread);
        assertEquals(0, again.failedMethods()); assertEquals(0, again.changedMethods());
        assertEquals(handlers(method(output, "orderedCatch"), "raise"), handlers(method(reread, "orderedCatch"), "raise"));
    }
}
