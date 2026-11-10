package me.naptila.deobfuscator.transformers.np.reflection;

import java.nio.file.*;
import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.junit.*;
import static org.junit.Assert.*;

public class DirectReflectionTest {
    DexContext dex; ReflectionModel model; MemberResolver resolver; ReflectionModel.Entry entry;
    @Before public void load() throws Exception {
        dex = new DexContext(DexFiles.read(Path.of(getClass().getResource("/np-batch3/reflect.dex").toURI())));
        model = new ReflectionModel(dex); resolver = new MemberResolver(dex, new LibraryTypes(List.of()));
        entry = model.dispatchers.values().stream().flatMap(m -> m.values().stream())
                .filter(e -> e.target().member() instanceof MethodReference m && m.getName().equals("shiftLong")).findFirst().orElseThrow();
    }
    MethodContext caller(boolean escape, boolean handler, boolean wrongWrapper, boolean boxedResult, boolean discarded) {
        var b = new MethodImplementationBuilder(8);
        b.addInstruction(Edits.constant(3, 2));
        b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 2, 3, new ImmutableTypeReference("[Ljava/lang/Object;")));
        b.addLabel("try");
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_WIDE_16, 4, -32));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, wrongWrapper ? 1 : 2, 4, 5, 0, 0, 0,
                ReflectionCode.ref(wrongWrapper ? "Ljava/lang/Integer;" : "Ljava/lang/Long;", "valueOf", List.of(wrongWrapper ? "I" : "J"), wrongWrapper ? "Ljava/lang/Integer;" : "Ljava/lang/Long;")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 6));
        b.addInstruction(Edits.constant(3, 0));
        b.addInstruction(new BuilderInstruction23x(Opcode.APUT_OBJECT, 6, 2, 3));
        // Reuse the original wide argument register before the reflected call.
        b.addInstruction(Edits.constant(4, 5));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 4, 0, 0, 0, 0, ReflectionCode.ref("Ljava/lang/Integer;", "valueOf", List.of("I"), "Ljava/lang/Integer;")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 6));
        b.addInstruction(Edits.constant(3, 1));
        b.addInstruction(new BuilderInstruction23x(Opcode.APUT_OBJECT, 6, 2, 3));
        b.addLabel("end");
        if (escape) b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 2, 0, 0, 0, 0, ReflectionCode.ref("Lprobe/Calls;", "consume", List.of("[Ljava/lang/Object;"), "V")));
        b.addInstruction(Edits.constant(0, entry.id())); b.addInstruction(Edits.constant(1, 0));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 3, 0, 1, 2, 0, 0, entry.dispatcher()));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        if (boxedResult) b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        else {
            b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 0, new ImmutableTypeReference("Ljava/lang/Long;")));
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0, ReflectionCode.ref("Ljava/lang/Long;", "longValue", List.of(), "J")));
            if (discarded) b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            else { b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_WIDE, 0)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0)); }
        }
        if (handler) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
            b.addInstruction(new BuilderInstruction12x(Opcode.ARRAY_LENGTH, 0, 2));
            b.addInstruction(new BuilderInstruction21s(Opcode.CONST_WIDE_16, 0, 0)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 0));
            b.addCatch("Ljava/lang/Exception;", b.getLabel("try"), b.getLabel("end"), b.getLabel("handler"));
        }
        Method method = new ImmutableMethod("Ldev/deobfuscator/fixture/cases/ArithmeticEdges;", "testDirect", List.of(), boxedResult ? "Ljava/lang/Object;" : discarded ? "V" : "J", 9, Set.of(), Set.of(), b.getMethodImplementation());
        return new MethodContext(dex, method);
    }
    int run(MethodContext context) { return new DirectReflectionCalls(model, resolver, (m, r, c) -> null).run(context); }
    @Test public void capturesWideArgumentsBeforeOriginalRegistersAreReused() {
        var context = caller(false, false, false, false, false); assertEquals(1, run(context)); ReflectionTransformer.cleanScaffolding(context);
        boolean target = false;
        for (var i : context.code().getInstructions()) {
            assertNotEquals(Opcode.NEW_ARRAY, i.getOpcode()); assertNotEquals(Opcode.APUT_OBJECT, i.getOpcode());
            if (i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m) {
                assertNotEquals("valueOf", m.getName()); assertNotEquals("longValue", m.getName());
                if (m.getName().equals("shiftLong")) { target = true; assertEquals(3, ((RegisterRangeInstruction)i).getRegisterCount()); }
            }
        }
        assertTrue(target);
    }
    @Test public void lastMoveIntoInvokeRegisterIsAProvenArrayAlias() {
        var context = caller(false, false, false, false, false);
        for (int n = 0; n < context.code().getInstructions().size(); n++) {
            var instruction = context.code().getInstructions().get(n);
            if (instruction instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m && Signatures.of(m).equals(Signatures.of(entry.dispatcher()))) {
                context.code().replaceInstruction(n, new BuilderInstruction35c(Opcode.INVOKE_STATIC, 3, 0, 1, 7, 0, 0, entry.dispatcher()));
                context.code().addInstruction(n, new BuilderInstruction32x(Opcode.MOVE_OBJECT_16, 7, 2)); break;
            }
        }
        assertEquals(1, run(context)); ReflectionTransformer.cleanScaffolding(context);
        for (var instruction : context.code().getInstructions()) assertNotEquals(Opcode.NEW_ARRAY, instruction.getOpcode());
    }
    @Test public void allocationMayBeTransferredOutOfLowEncodingRegisters() {
        var context = caller(false, false, false, false, false);
        for (int n = 0; n < context.code().getInstructions().size(); n++) {
            var instruction = context.code().getInstructions().get(n);
            if (instruction.getOpcode() == Opcode.APUT_OBJECT) {
                var r = (ThreeRegisterInstruction)instruction;
                context.code().replaceInstruction(n, new BuilderInstruction23x(Opcode.APUT_OBJECT, r.getRegisterA(), 7, r.getRegisterC()));
            }
            if (instruction instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m && Signatures.of(m).equals(Signatures.of(entry.dispatcher())))
                context.code().replaceInstruction(n, new BuilderInstruction35c(Opcode.INVOKE_STATIC, 3, 0, 1, 7, 0, 0, entry.dispatcher()));
        }
        context.code().addInstruction(2, new BuilderInstruction32x(Opcode.MOVE_OBJECT_16, 7, 2));
        assertEquals(1, run(context));
    }
    @Test public void escapingArrayRetainsDispatcher() { assertEquals(0, run(caller(true, false, false, false, false))); }
    @Test public void arrayObservedOnlyFromEarlierExceptionHandlerRetainsDispatcher() { assertEquals(0, run(caller(false, true, false, false, false))); }
    @Test public void reflectionNumericWideningRetainsDispatcher() { assertEquals(0, run(caller(false, false, true, false, false))); }
    @Test public void observableBoxedReturnIdentityRetainsDispatcher() { assertEquals(0, run(caller(false, false, false, true, false))); }
    @Test public void unusedPrimitiveUnboxingCanBeRemoved() { assertEquals(1, run(caller(false, false, false, false, true))); }
    @Test public void arrayAssignabilityDoesNotWidenPrimitiveComponents() {
        assertTrue(resolver.assignable("[Ljava/lang/String;", "[Ljava/lang/Object;"));
        assertTrue(resolver.assignable("[[I", "[Ljava/lang/Object;"));
        assertTrue(resolver.assignable("[I", "Ljava/lang/Cloneable;"));
        assertFalse(resolver.assignable("[I", "[J")); assertFalse(resolver.assignable("I", "Ljava/lang/Object;"));
    }
}
