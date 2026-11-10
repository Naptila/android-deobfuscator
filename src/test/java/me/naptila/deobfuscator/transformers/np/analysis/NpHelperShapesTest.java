package me.naptila.deobfuscator.transformers.np.analysis;

import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.MethodContext;
import me.naptila.deobfuscator.dex.Signatures;
import me.naptila.deobfuscator.transformers.np.NpCleanup;
import me.naptila.deobfuscator.transformers.np.strings.NpStringCalls;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.jf.dexlib2.immutable.value.ImmutableIntEncodedValue;
import org.junit.Test;
import static org.junit.Assert.*;

public class NpHelperShapesTest {
    static final String OWNER = "Lshapes/Helper;";
    static final int PUBLIC_STATIC = AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue();
    static final ImmutableFieldReference FIELD = new ImmutableFieldReference(OWNER, "flag", "I");
    static void constant(MethodImplementationBuilder b, int r, int n) { b.addInstruction(new BuilderInstruction31i(Opcode.CONST, r, n)); }
    static Method method(String name, List<ImmutableMethodParameter> args, String ret, MethodImplementationBuilder b) {
        return new ImmutableMethod(OWNER, name, args, ret, PUBLIC_STATIC, Set.of(), Set.of(), b.getMethodImplementation());
    }
    static Method guard(boolean effect) {
        var b = new MethodImplementationBuilder(4);
        constant(b, 0, 292);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 1, FIELD));
        b.addInstruction(new BuilderInstruction30t(Opcode.GOTO_32, b.getLabel("start")));
        b.addLabel("end"); b.addInstruction(new BuilderInstruction23x(Opcode.OR_INT, 0, 2, 3));
        if (effect) b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Lprobe/Effects;", "run", List.of(), "V")));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("start"); b.addInstruction(new BuilderInstruction23x(Opcode.AND_INT, 2, 0, 1));
        b.addInstruction(new BuilderInstruction12x(Opcode.NOT_INT, 1, 1));
        b.addInstruction(new BuilderInstruction22s(Opcode.AND_INT_LIT16, 3, 1, -293));
        b.addInstruction(new BuilderInstruction30t(Opcode.GOTO_32, b.getLabel("end")));
        return method("guard", List.of(), "I", b);
    }
    static Method hash(boolean wrongArgument) {
        var b = new MethodImplementationBuilder(4);
        b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_OBJECT_16, 0, 3));
        if (wrongArgument) constant(b, 0, 0);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/Object;", "hashCode", List.of(), "I")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 1));
        b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_16, 2, 1));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 2));
        return method("hash", List.of(new ImmutableMethodParameter("Ljava/lang/Object;", Set.of(), "arg")), "I", b);
    }
    @Test public void provesBitwiseGuardWithCopiesAndGotosButRejectsExtraEffects() {
        var summary = NpHelpers.guard(guard(false));
        assertNotNull(summary); assertEquals(-293, summary.key()); assertEquals(Signatures.of(FIELD), summary.field());
        assertNull(NpHelpers.guard(guard(true)));
        assertTrue(NpHelpers.hash(hash(false))); assertFalse(NpHelpers.hash(hash(true)));
    }
    @Test public void modeledResultsDoNotMakeClassInitializationRemovable() {
        var init = new MethodImplementationBuilder(0);
        init.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Lprobe/Effects;", "run", List.of(), "V")));
        init.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        var field = new ImmutableField(OWNER, "flag", "I", PUBLIC_STATIC, new ImmutableIntEncodedValue(123), Set.of(), Set.of());
        var cls = new ImmutableClassDef(OWNER, AccessFlags.PUBLIC.getValue(), "Ljava/lang/Object;", List.of(), null,
                Set.of(), List.of(field), List.of(guard(false), hash(false), method("<clinit>", List.of(), "V", init)));
        var dex = new DexContext(new ImmutableDexFile(Opcodes.forApi(28), List.of(cls)));
        var helpers = new NpHelpers(dex);
        assertTrue(helpers.hashes.contains(Signatures.of(hash(false))));
        assertTrue(helpers.guards.containsKey(Signatures.of(guard(false))));
        assertFalse(helpers.removableHashes.contains(Signatures.of(hash(false))));
        assertFalse(helpers.removableGuards.contains(Signatures.of(guard(false))));
    }
    @Test public void normalizedDecodersKeepRemovalProofOnlyWithHarmlessTableInitialization() {
        for (String mode : List.of("table", "empty", "business", "public-table", "superclass", "decoder-effect")) {
            var table = new ImmutableFieldReference(OWNER, "short", "[S");
            var b = new MethodImplementationBuilder(3);
            constant(b, 0, 1);
            b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 0, 0, new ImmutableTypeReference("[S")));
            constant(b, 1, 0); constant(b, 2, 42);
            b.addInstruction(new BuilderInstruction23x(Opcode.APUT_SHORT, 2, 0, 1));
            b.addInstruction(new BuilderInstruction21c(Opcode.SPUT_OBJECT, 0, table));
            if (mode.equals("business")) b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                    new ImmutableMethodReference("Lprobe/Effects;", "run", List.of(), "V")));
            b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            if (mode.equals("empty")) {
                b = new MethodImplementationBuilder(0); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            }
            Method template = NpDecoderShapeTest.decoder("");
            var code = new MutableMethodImplementation(template.getImplementation());
            code.addInstruction(0, mode.equals("decoder-effect") ? new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                    new ImmutableMethodReference("Lprobe/Effects;", "run", List.of(), "V")) : new BuilderInstruction10x(Opcode.NOP));
            var decoder = new ImmutableMethod(OWNER, "decode", template.getParameters(), template.getReturnType(), PUBLIC_STATIC, Set.of(), Set.of(), code);
            var field = new ImmutableField(OWNER, "flag", "I", PUBLIC_STATIC, new ImmutableIntEncodedValue(123), Set.of(), Set.of());
            var shortField = new ImmutableField(OWNER, "short", "[S", (mode.equals("public-table") ? AccessFlags.PUBLIC : AccessFlags.PRIVATE).getValue()
                    | AccessFlags.STATIC.getValue() | AccessFlags.FINAL.getValue(), null, Set.of(), Set.of());
            var cls = new ImmutableClassDef(OWNER, 1, mode.equals("superclass") ? "Lprobe/Parent;" : "Ljava/lang/Object;", List.of(), null,
                    Set.of(), List.of(field, shortField), List.of(guard(false), hash(false), decoder, method("<clinit>", List.of(), "V", b)));
            var dex = new DexContext(new ImmutableDexFile(Opcodes.forApi(28), List.of(cls)));
            var model = NpAnalysis.of(dex).model();
            assertEquals(mode, Set.of("table", "empty", "decoder-effect").contains(mode), NpStringCalls.initializationSafe(dex, OWNER, "Lother/Caller;"));
            assertEquals(mode, mode.equals("table") || mode.equals("empty"), model.helpers().removableDecoders().contains(Signatures.of(decoder)));
        }
    }
    @Test public void scratchNormalizationPreservesTheFieldDependency() {
        var guarded = new MutableMethodImplementation(guard(false).getImplementation());
        guarded.addInstruction(0, new BuilderInstruction21c(Opcode.CONST_STRING, 3, new ImmutableStringReference("dispatch")));
        guarded.addInstruction(1, new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 3, 0, 0, 0, 0, hash(false)));
        Method hidden = new ImmutableMethod(OWNER, "guard", List.of(), "I", PUBLIC_STATIC, Set.of(), Set.of(), guarded);
        assertNull(NpHelpers.guard(hidden));
        Method template = NpDecoderShapeTest.decoder("");
        Method decoder = new ImmutableMethod(OWNER, "decode", template.getParameters(), template.getReturnType(), PUBLIC_STATIC,
                Set.of(), Set.of(), template.getImplementation());
        var field = new ImmutableField(OWNER, "flag", "I", PUBLIC_STATIC, new ImmutableIntEncodedValue(123), Set.of(), Set.of());
        var cls = new ImmutableClassDef(OWNER, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(field), List.of(hidden, hash(false), decoder));
        var dex = new DexContext(new ImmutableDexFile(Opcodes.forApi(28), List.of(cls)));
        var model = NpAnalysis.of(dex).model;
        assertEquals(new NpHelpers.Guard(Signatures.of(FIELD), -293), model.helpers.guards.get(Signatures.of(hidden)));
        assertEquals(Integer.valueOf(123), model.fields.get(Signatures.of(FIELD)));
        assertEquals(Opcode.CONST_STRING, new CodeGraph(dex.methods().get(Signatures.of(hidden)).getImplementation()).at(0).getOpcode());
        assertTrue("Scratch analysis must not register restoration evidence", dex.evidence().snapshot().candidates().isEmpty());
    }
    @Test public void cleanupKeepsInaccessibleCallsAndFields() {
        Method h = hash(false);
        var privateHash = new ImmutableMethod(OWNER, h.getName(), h.getParameters(), h.getReturnType(), 10,
                Set.of(), Set.of(), h.getImplementation());
        var field = new ImmutableField(OWNER, "flag", "I", 10, new ImmutableIntEncodedValue(123), Set.of(), Set.of());
        var helper = new ImmutableClassDef(OWNER, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(field), List.of(privateHash, guard(false)));
        var b = new MethodImplementationBuilder(2);
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("known")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, privateHash));
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 1, FIELD));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        var caller = new ImmutableMethod("Lother/Caller;", "run", List.of(), "V", PUBLIC_STATIC, Set.of(), Set.of(), b.getMethodImplementation());
        var cls = new ImmutableClassDef(caller.getDefiningClass(), 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(caller));
        var dex = new DexContext(new ImmutableDexFile(Opcodes.forApi(28), List.of(helper, cls)));
        var pass = new NpCleanup(); pass.prepare(dex);
        var context = new MethodContext(dex, caller); pass.run(context);
        assertTrue(context.code().getInstructions().stream().anyMatch(i -> i.getOpcode() == Opcode.INVOKE_STATIC));
        assertTrue(context.code().getInstructions().stream().anyMatch(i -> i.getOpcode() == Opcode.SGET));
    }
}
