package me.naptila.deobfuscator.transformers.np.reflection;

import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.Edits;
import me.naptila.deobfuscator.dex.MethodContext;
import me.naptila.deobfuscator.dex.Signatures;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.reference.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class StringContentUsesTest {
    static final String STR = "Ljava/lang/String;", OBJ = "Ljava/lang/Object;";
    static final MethodReference CACHE = ReflectionCode.ref("LTest;", "cache", List.of("I", STR), STR);
    MethodImplementationBuilder start() {
        var b = new MethodImplementationBuilder(6);
        b.addInstruction(Edits.constant(2, 1)); b.addInstruction(Edits.constant(3, "abc"));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 2, 3, 0, 0, 0, CACHE));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0)); return b;
    }
    MethodContext context(MethodImplementationBuilder b) {
        return new MethodContext(new ImmutableMethod("LTest;", "caller", List.of(), OBJ, 9, Set.of(), Set.of(), b.getMethodImplementation()));
    }
    void done(MethodImplementationBuilder b) { b.addInstruction(Edits.constant(1, 0)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 1)); }
    boolean only(MethodImplementationBuilder b) {
        var c = context(b); var g = c.graph(); return StringContentUses.onlyContent(g, new ReflectionTypes(c.original(), g), 3);
    }
    @Test public void aliasesUsedForStringContentCanBecomeLiterals() {
        var b = start(); b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 4, 0));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 4, 0, 0, 0, 0, ReflectionCode.ref(STR, "hashCode", List.of(), "I"))); done(b);
        assertTrue(only(b)); assertEquals(1, ReflectionTransformer.cleanStrings(context(b), Map.of(Signatures.of(CACHE), false)));
    }
    @Test public void appendCopiesContentAndDoesNotTaintTheBuilderResult() {
        var b = start(); b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 1, new ImmutableTypeReference("Ljava/lang/StringBuilder;")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 1, 0, 0, 0, 0, ReflectionCode.ref("Ljava/lang/StringBuilder;", "<init>", List.of(), "V")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, 1, 0, 0, 0, 0, ReflectionCode.ref("Ljava/lang/StringBuilder;", "append", List.of(STR), "Ljava/lang/StringBuilder;")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 1)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 1)); assertTrue(only(b));
    }
    @Test public void referenceComparisonThroughAliasRetainsCache() {
        var b = start(); b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 4, 0));
        b.addInstruction(new BuilderInstruction22t(Opcode.IF_EQ, 4, 3, b.getLabel("end"))); b.addLabel("end"); done(b); assertFalse(only(b));
    }
    @Test public void escapingReturnFieldAndArrayRetainCache() {
        var b = start(); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0)); assertFalse(only(b));
        b = start(); b.addInstruction(new BuilderInstruction21c(Opcode.SPUT_OBJECT, 0, new ImmutableFieldReference("LTest;", "stored", STR))); done(b); assertFalse(only(b));
        b = start(); b.addInstruction(new BuilderInstruction23x(Opcode.APUT_OBJECT, 0, 4, 2)); done(b); assertFalse(only(b));
    }
    @Test public void identityAndMonitorOperationsRetainCache() {
        var b = start(); b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, ReflectionCode.ref("Ljava/lang/System;", "identityHashCode", List.of(OBJ), "I"))); done(b); assertFalse(only(b));
        b = start(); b.addInstruction(new BuilderInstruction11x(Opcode.MONITOR_ENTER, 0)); b.addInstruction(new BuilderInstruction11x(Opcode.MONITOR_EXIT, 0)); done(b); assertFalse(only(b));
    }
    @Test public void identityReturningStringOperationAndUnknownConsumerStay() {
        var b = start(); b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0, ReflectionCode.ref(STR, "toString", List.of(), STR))); done(b); assertFalse(only(b));
        b = start(); b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, ReflectionCode.ref("LUnknown;", "sink", List.of(STR), "V"))); done(b); assertFalse(only(b));
    }
    @Test public void androidLogsConsumeContentButTextViewCanRetainTheReference() {
        var b = start(); b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 2, 0, 3, 0, 0, 0, ReflectionCode.ref("Landroid/util/Log;", "e", List.of(STR, STR), "I"))); done(b); assertTrue(only(b));
        b = start(); b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, 4, 0, 0, 0, 0, ReflectionCode.ref("Landroid/widget/TextView;", "setText", List.of("Ljava/lang/CharSequence;"), "V"))); done(b); assertFalse(only(b));
    }
    @Test public void allBranchesAndExceptionalAliasesAreChecked() {
        var b = start(); b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 2, b.getLabel("escape")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0, ReflectionCode.ref(STR, "length", List.of(), "I"))); done(b);
        b.addLabel("escape"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0)); assertFalse(only(b));
        b = start(); b.addLabel("try"); b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, ReflectionCode.ref("LUnknown;", "mightThrow", List.of(), "V")));
        b.addLabel("end"); b.addInstruction(Edits.constant(0, 0)); done(b);
        b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        b.addCatch("Ljava/lang/Exception;", b.getLabel("try"), b.getLabel("end"), b.getLabel("handler")); assertFalse(only(b));
    }
    @Test public void internedResultCanReturnLiteralButAllocatedResultCannot() {
        var b = start(); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        assertEquals(0, ReflectionTransformer.cleanStrings(context(b), Map.of(Signatures.of(CACHE), false)));
        assertEquals(1, ReflectionTransformer.cleanStrings(context(b), Map.of(Signatures.of(CACHE), true)));
    }
    @Test public void provenLiteralAlsoRemovesItsRedundantStringCast() {
        var b = start(); b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 0, new ImmutableTypeReference(STR)));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0, ReflectionCode.ref(STR, "length", List.of(), "I"))); done(b);
        var c = context(b); assertEquals(1, ReflectionTransformer.cleanStrings(c, Map.of(Signatures.of(CACHE), false)));
        for (var instruction : c.code().getInstructions()) assertNotEquals(Opcode.CHECK_CAST, instruction.getOpcode());
    }
    @Test public void helperProvenanceIsRequired() {
        var b = start(); done(b); assertTrue(only(b)); assertEquals(0, ReflectionTransformer.cleanStrings(context(b), Map.of()));
    }
}
