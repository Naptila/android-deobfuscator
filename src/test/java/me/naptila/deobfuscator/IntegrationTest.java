package me.naptila.deobfuscator;

import java.io.*;
import java.nio.file.*;
import java.util.*;

import me.naptila.deobfuscator.core.Pass;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.core.Pipeline;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.strings.XorStringDecoder;
import me.naptila.deobfuscator.transformers.cleanup.ConstantSwitchTransformer;
import me.naptila.deobfuscator.transformers.cleanup.UnreachableCodeTransformer;
import me.naptila.deobfuscator.transformers.np.controlflow.DispatcherTransformer;
import me.naptila.deobfuscator.transformers.np.numbers.NumberTransformer;
import me.naptila.deobfuscator.transformers.cleanup.*;
import me.naptila.deobfuscator.transformers.strings.StringDecryptTransformer;
import me.naptila.deobfuscator.cli.Main;
import me.naptila.deobfuscator.core.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.strings.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.immutable.reference.ImmutableMethodReference;
import org.jf.dexlib2.writer.pool.DexPool;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class IntegrationTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    private List<DexPass> passes() {
        return List.of(new StringDecryptTransformer(List.of(new XorStringDecoder(Fixtures.DECODE))), new NumberTransformer(), new DispatcherTransformer(),
                new ConstantSwitchTransformer(), new UnreachableCodeTransformer());
    }
    private Method transform(Method method) {
        DexEngine.Result result = new DexEngine(passes(), 20).transform(Fixtures.npDex(method));
        assertEquals(result.methods().toString(), 0, result.failedMethods());
        assertTrue(result.methods().toString(), result.methods().stream().allMatch(DexEngine.MethodReport::converged));
        return Fixtures.first(result.dex());
    }
    @Test public void restoresBothBranchPathsAndDispatcherRegisterOutputs() throws Exception {
        for (boolean expanded : new boolean[]{false, true}) for (boolean fallthrough : new boolean[]{false, true}) {
            Method original = Fixtures.flattened(expanded, fallthrough, false);
            Method restored = transform(original);
            for (int input : new int[]{Integer.MIN_VALUE, -1, 0, 1, Integer.MAX_VALUE}) {
                assertEquals(input > 0 ? "yes".hashCode() : "no".hashCode(), Fixtures.execute(original, input));
                assertEquals(Fixtures.execute(original, input), Fixtures.execute(restored, input));
            }
            for (Instruction insn : restored.getImplementation().getInstructions()) assertFalse(CodeGraph.isSwitch(insn.getOpcode()));
            Path dex = directory.getRoot().toPath().resolve("result-" + expanded + "-" + fallthrough + ".dex");
            DexPool.writeTo(dex.toString(), Fixtures.npDex(restored));
            Method reread = Fixtures.first(DexFileFactory.loadDexFile(dex.toFile(), null));
            assertEquals(Fixtures.execute(original, 42), Fixtures.execute(reread, 42));
            DexEngine.Result again = new DexEngine(passes(), 20).transform(Fixtures.npDex(reread));
            assertEquals(0, again.changedMethods());
        }
    }
    @Test public void preservesUnknownStateAndTryRegions() {
        Method original = Fixtures.flattened(false, false, true);
        Method rewritten = transform(original);
        assertEquals(original.getImplementation().getTryBlocks().size(), rewritten.getImplementation().getTryBlocks().size());
        assertTrue(new CodeGraph(rewritten.getImplementation()).size() > 0);
        Method unknown = Fixtures.encryptedString(true);
        DexEngine.Result result = new DexEngine(passes(), 20).transform(Fixtures.dex(unknown));
        assertEquals(0, result.changedMethods());
    }
    @Test public void decryptsUtf16StringsAndRetainsOriginalCall() {
        Method original = Fixtures.encryptedString(false), rewritten = transform(original);
        assertEquals("中文🙂 secret", Fixtures.execute(original, 0));
        assertEquals(Fixtures.execute(original, 0), Fixtures.execute(rewritten, 0));
        boolean retainedCall = false, plaintext = false;
        for (Instruction insn : rewritten.getImplementation().getInstructions()) {
            retainedCall |= insn.getOpcode() == Opcode.INVOKE_STATIC;
            plaintext |= insn.getOpcode() == Opcode.CONST_STRING_JUMBO;
        }
        assertTrue(retainedCall); assertTrue(plaintext);
        DexEngine.Result wrongSignature = new DexEngine(List.of(new StringDecryptTransformer(List.of(
                new XorStringDecoder("Lother/Crypto;->decode(Ljava/lang/String;I)Ljava/lang/String;")))), 5).transform(Fixtures.dex(original));
        assertEquals(0, wrongSignature.changedMethods());
    }
    @Test public void stringAndControlFlowModulesCooperateWithoutSpecialCoupling() {
        Method original = Fixtures.flattened(true, true, false, true);
        Method restored = transform(original);
        for (int input : new int[]{-1, 0, 1}) assertEquals(Fixtures.execute(original, input), Fixtures.execute(restored, input));
        for (Instruction insn : restored.getImplementation().getInstructions()) assertFalse(CodeGraph.isSwitch(insn.getOpcode()));
        // With no decoder configured, the unknown state prevents dispatcher folding.
        DexEngine.Result unknown = new DexEngine(List.of(new DispatcherTransformer(), new ConstantSwitchTransformer()), 20).transform(Fixtures.npDex(original));
        assertEquals(0, unknown.changedMethods());
    }
    @Test public void unknownInvokeInvalidatesPendingResultAndWideWriteKillsBothRegisters() {
        Constants state = new Constants(); state.put(0, "abc");
        ConstantEvaluator.step(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0, Fixtures.HASH), state);
        ConstantEvaluator.step(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Lsample/X;", "unknown", List.of(), "I")), state);
        ConstantEvaluator.step(new BuilderInstruction11x(Opcode.MOVE_RESULT, 1), state);
        assertNull(state.get(1));
        state.put(1, 123); state.put(2, 456);
        ConstantEvaluator.step(new BuilderInstruction21s(Opcode.CONST_WIDE_16, 1, 100), state);
        assertNull(state.get(1)); assertNull(state.get(2));
    }
    @Test public void constantAnalysisDoesNotMergeDifferentBranchValuesAsOneConstant() {
        Method method = Fixtures.flattened(false, false, false);
        CodeGraph graph = new CodeGraph(method.getImplementation()); ConstantAnalysis analysis = new ConstantAnalysis(graph);
        boolean found = false;
        for (int i = 0; i < graph.size(); i++) if (CodeGraph.isSwitch(graph.at(i).getOpcode())) {
            found = true; assertNull(analysis.before(i).get(0)); assertEquals(-123456789, analysis.before(i).get(1));
        }
        assertTrue(found);
    }
    @Test public void failingPassRollsBackOnlyItsMethod() {
        DexPass broken = new DexPass() {
            public String id() { return "test.failure"; }
            public PassResult run(MethodContext context) {
                context.code().replaceInstruction(0, new BuilderInstruction10x(Opcode.NOP));
                throw new IllegalStateException("test rollback");
            }
        };
        Method original = Fixtures.flattened(false, false, false);
        DexEngine.Result result = new DexEngine(List.of(broken), 2).transform(Fixtures.dex(original));
        assertEquals(1, result.failedMethods()); assertEquals(0, result.changedMethods());
        assertEquals(Fixtures.execute(original, 1), Fixtures.execute(Fixtures.first(result.dex()), 1));
    }
    @Test public void pipelineReportsIterationLimitAndDuplicateIds() {
        Pass<int[]> forever = new Pass<>() {
            public String id() { return "test.forever"; }
            public PassResult run(int[] value) { value[0]++; return PassResult.changed(1); }
        };
        Pipeline.Result result = new Pipeline<>(List.of(forever), 3).run(new int[1]);
        assertFalse(result.converged()); assertEquals(3, result.edits());
        assertThrows(IllegalArgumentException.class, () -> new Pipeline<>(List.of(forever, forever), 3));
    }
    @Test public void cliWritesReadableDexAndReportAndNeverOverwritesInput() throws Exception {
        Path root = directory.getRoot().toPath(), input = root.resolve("input.dex"), output = root.resolve("output.dex"), report = root.resolve("report.json");
        DexPool.writeTo(input.toString(), Fixtures.npDex(Fixtures.flattened(true, false, false)));
        byte[] original = Files.readAllBytes(input);
        ByteArrayOutputStream messages = new ByteArrayOutputStream(); PrintStream log = new PrintStream(messages);
        assertEquals(messages.toString(), 0, Main.run(new String[]{"--input", input.toString(), "--output", output.toString(), "--report", report.toString(),
                "--transformers", "np.numbers,np.dispatcher,dex.constant-switch,dex.unreachable"}, log, log));
        assertTrue(Files.readString(report).contains("\"changedMethods\": 1"));
        assertEquals("yes".hashCode(), Fixtures.execute(Fixtures.first(DexFileFactory.loadDexFile(output.toFile(), null)), 1));
        assertEquals(1, Main.run(new String[]{"--input", input.toString(), "--output", input.toString()}, log, log));
        assertArrayEquals(original, Files.readAllBytes(input));
        assertEquals(1, Main.run(new String[]{"--input", input.toString(), "--output", output.toString()}, log, log));
        Path dryOutput = root.resolve("dry.dex");
        assertEquals(0, Main.run(new String[]{"--input", input.toString(), "--output", dryOutput.toString(), "--dry-run"}, log, log));
        assertFalse(Files.exists(dryOutput));
        assertEquals(1, Main.run(new String[]{"--input", input.toString(), "--dry-run", "--passes", "not-a-pass"}, log, log));
    }
}
