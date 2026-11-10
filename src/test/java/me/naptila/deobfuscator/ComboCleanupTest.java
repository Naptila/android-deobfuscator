package me.naptila.deobfuscator;

import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.transformers.cleanup.UnreachableCodeTransformer;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.immutable.reference.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class ComboCleanupTest {
    private static final ImmutableMethodReference CALL = new ImmutableMethodReference("Lsample/Effect;", "consume", List.of("Ljava/lang/String;"), "V");
    private static void consume(MethodImplementationBuilder b, int register) {
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, register, 0, 0, 0, 0, CALL));
    }
    @Test public void inverseMovesKeepFirstAssignmentAndRejectSeparateEntriesAndWideOverlap() {
        for (boolean entry : List.of(false, true)) {
            var b = new MethodImplementationBuilder(3);
            if (entry) { Fixtures.integer(b, 2, 0); b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 2, b.getLabel("second"))); }
            b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 0, 1));
            b.addLabel("second"); b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 1, 0));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
            var context = new MethodContext(Fixtures.method("copies", List.of(), "Ljava/lang/Object;", b.getMethodImplementation()));
            assertEquals(entry ? 0 : 1, RedundantMoves.run(context));
        }
        for (int source : new int[]{1, 2}) {
            var b = new MethodImplementationBuilder(4);
            b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_WIDE, 0, source));
            b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_WIDE, source, 0));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
            var context = new MethodContext(Fixtures.method("wide", List.of(), "J", b.getMethodImplementation()));
            assertEquals(source == 1 ? 0 : 1, RedundantMoves.run(context));
        }
    }
    @Test public void interleavedObjectAndWideCopiesKeepLiveValues() {
        var b = new MethodImplementationBuilder(20);
        b.addInstruction(new BuilderInstruction22x(Opcode.MOVE_OBJECT_FROM16, 0, 16));
        b.addInstruction(new BuilderInstruction22x(Opcode.MOVE_OBJECT_FROM16, 1, 17));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 2, 0));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 3, 1));
        b.addInstruction(new BuilderInstruction22x(Opcode.MOVE_WIDE_FROM16, 4, 18));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_WIDE, 6, 4));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 0, 2));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 1, 3));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_WIDE, 4, 6));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 2, 0));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 3, 1));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_WIDE, 6, 4));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0, Fixtures.HASH));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 8));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 1, 0, 0, 0, 0, Fixtures.HASH));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 9));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 8, 8, 9));
        b.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_LONG, 8, 8));
        b.addInstruction(new BuilderInstruction23x(Opcode.XOR_LONG, 8, 8, 4));
        b.addInstruction(new BuilderInstruction23x(Opcode.XOR_LONG, 8, 8, 6));
        b.addInstruction(new BuilderInstruction23x(Opcode.ADD_LONG, 8, 8, 4));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 8));
        Method original = Fixtures.method("interleaved", List.of(
                new org.jf.dexlib2.immutable.ImmutableMethodParameter("Ljava/lang/String;", Set.of(), "left"),
                new org.jf.dexlib2.immutable.ImmutableMethodParameter("Ljava/lang/String;", Set.of(), "right"),
                new org.jf.dexlib2.immutable.ImmutableMethodParameter("J", Set.of(), "token")), "J", b.getMethodImplementation());
        var context = new MethodContext(original);
        assertEquals(6, RedundantMoves.run(context)); assertEquals(0, RedundantMoves.run(context));
        var before = new NpNumericInterpreter(Fixtures.dex(original));
        var after = new NpNumericInterpreter(Fixtures.dex(context.finish()));
        for (String left : List.of("", "left", "中文😀")) for (String right : List.of("", "right"))
            for (long token : new long[]{Long.MIN_VALUE, 0, Long.MAX_VALUE}) {
                long expected = (long)(left.hashCode() + right.hashCode()) + token;
                assertEquals(expected, before.run(Signatures.of(original), left, right, token));
                assertEquals(expected, after.run(Signatures.of(original), left, right, token));
            }
    }
    @Test public void copyProofStopsAtWritesCastsAndPartialWideOverwrites() {
        for (boolean cast : new boolean[]{false, true}) {
            var b = new MethodImplementationBuilder(4);
            b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 0, 2));
            b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 1, 0));
            if (cast) b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 1, new ImmutableTypeReference("Ljava/lang/String;")));
            else b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 1, 3));
            b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 0, 1));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
            var context = new MethodContext(Fixtures.method("overwrite", List.of(), "Ljava/lang/Object;", b.getMethodImplementation()));
            assertEquals(0, RedundantMoves.run(context));
        }
        var b = new MethodImplementationBuilder(8);
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_WIDE, 0, 2));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_WIDE, 3, 6));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_WIDE, 2, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 2));
        var context = new MethodContext(Fixtures.method("partial", List.of(), "J", b.getMethodImplementation()));
        assertEquals(0, RedundantMoves.run(context));
    }
    @Test public void copiesAcrossJoinsRequireEqualRegistersOnEveryIncomingPath() {
        for (boolean divergent : new boolean[]{false, true}) {
            var b = new MethodImplementationBuilder(4);
            b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 0, 2));
            b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 3, b.getLabel("other")));
            b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 1, 0)); Fixtures.go(b, "join");
            b.addLabel("other"); b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 1, divergent ? 3 : 0));
            b.addLabel("join"); b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 0, 1));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
            Method input = Fixtures.method("joinCopies", List.of(
                    new org.jf.dexlib2.immutable.ImmutableMethodParameter("I", Set.of(), "value"),
                    new org.jf.dexlib2.immutable.ImmutableMethodParameter("I", Set.of(), "condition")), "I", b.getMethodImplementation());
            var context = new MethodContext(input);
            assertEquals(divergent ? 0 : 1, RedundantMoves.run(context)); assertEquals(0, RedundantMoves.run(context));
            var before = new NpNumericInterpreter(Fixtures.dex(input)); var after = new NpNumericInterpreter(Fixtures.dex(context.finish()));
            for (int value : new int[]{Integer.MIN_VALUE, -1, 0, 1, Integer.MAX_VALUE})
                for (int condition : new int[]{-1, 0, 1}) {
                    int expected = divergent && condition == 0 ? condition : value;
                    assertEquals(expected, before.run(Signatures.of(input), value, condition));
                    assertEquals(expected, after.run(Signatures.of(input), value, condition));
                }
        }
    }
    @Test public void exceptionEntriesDoNotInheritNormalPathCopyProofs() {
        var b = new MethodImplementationBuilder(8);
        Fixtures.string(b, 0, "normal"); Fixtures.string(b, 1, "caught"); Fixtures.integer(b, 3, 0);
        b.addLabel("try"); b.addInstruction(new BuilderInstruction23x(Opcode.AGET_BYTE, 3, 7, 3));
        b.addLabel("end"); b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 1, 0)); Fixtures.go(b, "join");
        b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 2)); Fixtures.go(b, "join");
        b.addLabel("join"); b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 0, 1));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        b.addCatch(b.getLabel("try"), b.getLabel("end"), b.getLabel("handler"));
        Method input = Fixtures.method("catchCopies", List.of(
                new org.jf.dexlib2.immutable.ImmutableMethodParameter("[B", Set.of(), "array")), "Ljava/lang/String;", b.getMethodImplementation());
        var context = new MethodContext(input); assertEquals(0, RedundantMoves.run(context));
        var before = new NpNumericInterpreter(Fixtures.dex(input)); var after = new NpNumericInterpreter(Fixtures.dex(context.finish()));
        for (byte[] value : new byte[][]{null, new byte[0], new byte[]{7}}) {
            String expected = value != null && value.length > 0 ? "normal" : "caught";
            assertEquals(expected, before.run(Signatures.of(input), (Object)value));
            assertEquals(expected, after.run(Signatures.of(input), (Object)value));
        }
    }
    @Test public void nopRoutesAreThreadedButAnInfiniteNopCycleStaysInfinite() {
        var b = new MethodImplementationBuilder(1); Fixtures.go(b, "nop");
        b.addLabel("value"); Fixtures.integer(b, 0, 7); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("nop"); b.addInstruction(new BuilderInstruction10x(Opcode.NOP)); Fixtures.go(b, "value");
        var context = new MethodContext(Fixtures.method("route", List.of(), "I", b.getMethodImplementation()));
        assertTrue(BranchThreading.run(context) > 0); new UnreachableCodeTransformer().run(context);
        assertEquals(7, new NpNumericInterpreter(Fixtures.dex(context.finish())).run(Signatures.of(context.finish())));
        b = new MethodImplementationBuilder(1); b.addLabel("cycle"); b.addInstruction(new BuilderInstruction10x(Opcode.NOP)); Fixtures.go(b, "cycle");
        context = new MethodContext(Fixtures.method("cycle", List.of(), "V", b.getMethodImplementation()));
        assertEquals(0, BranchThreading.run(context));
        assertEquals(List.of(0), context.graph().successors(1));
    }
    private Method literal(boolean protectLiteral, boolean liveScratch, boolean branch, boolean unsupportedUse) {
        var b = new MethodImplementationBuilder(3);
        Fixtures.string(b, 0, "old"); Fixtures.string(b, 2, "live");
        b.addLabel("start"); consume(b, 0);
        if (!protectLiteral) b.addLabel("end");
        Fixtures.string(b, 0, "new"); consume(b, 0);
        if (liveScratch) Fixtures.integer(b, 1, 42);
        if (branch) { Fixtures.integer(b, 1, 0); b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 1, b.getLabel("last"))); }
        if (unsupportedUse) b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 1, 0));
        b.addLabel("last"); consume(b, 0);
        if (protectLiteral) b.addLabel("end");
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1)); consume(b, 0);
        if (liveScratch) consume(b, 2);
        b.addInstruction(new BuilderInstruction11x(Opcode.THROW, 1));
        b.addCatch(b.getLabel("start"), b.getLabel("end"), b.getLabel("handler"));
        return Fixtures.method("literal", List.of(), "V", b.getMethodImplementation());
    }
    @Test public void handlerLiteralUsesADeadRegisterAndKeepsCallsAndProtection() {
        var context = new MethodContext(literal(false, false, false, false)); CodeGraph before = context.graph();
        assertEquals(1, HandlerLiteralRegisters.run(context)); CodeGraph after = context.graph();
        assertEquals(before.size(), after.size());
        // v0 is live in the handler; v1 holds the exception there, but is dead at handler entry.
        int changed = 0;
        for (int i = 0; i < before.size(); i++) {
            assertEquals(before.protection(i), after.protection(i));
            if (before.at(i) instanceof VariableRegisterInstruction)
                if (!Arrays.equals(ConstantEvaluator.arguments(before.at(i)), ConstantEvaluator.arguments(after.at(i)))) changed++;
        }
        assertEquals(2, changed); assertEquals(0, HandlerLiteralRegisters.run(context));
    }
    @Test public void literalRemappingRejectsProtectedOrSplitOrUnsupportedLifetimes() {
        for (Method method : List.of(literal(true, false, false, false), literal(false, false, true, false),
                literal(false, false, false, true), literal(false, true, false, false)))
            assertEquals(0, HandlerLiteralRegisters.run(new MethodContext(method)));
    }
}
