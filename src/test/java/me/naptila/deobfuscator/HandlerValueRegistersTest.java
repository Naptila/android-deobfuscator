package me.naptila.deobfuscator;

import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.Edits;
import me.naptila.deobfuscator.dex.HandlerValueRegisters;
import me.naptila.deobfuscator.dex.MethodContext;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class HandlerValueRegistersTest {
    MethodContext code(boolean protectDefinition, boolean laterUse) {
        var b = new MethodImplementationBuilder(5);
        b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 2, new ImmutableTypeReference("Ljava/lang/Object;")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 1, 2, 0, 0, 0, 0, new ImmutableMethodReference("Ljava/lang/Object;", "<init>", List.of(), "V")));
        b.addLabel("try");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, new ImmutableMethodReference("LCalls;", "mightThrow", List.of(), "V")));
        if (!protectDefinition) b.addLabel("end");
        b.addInstruction(Edits.constant(2, 7));
        b.addInstruction(new BuilderInstruction32x(Opcode.MOVE_16, 3, 2));
        if (protectDefinition) b.addLabel("end");
        if (laterUse) b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT, 3, 3, 2));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 3));
        b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 2, 0, 0, 0, 0, new ImmutableMethodReference("Ljava/lang/Object;", "hashCode", List.of(), "I")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addCatch("Ljava/lang/Exception;", b.getLabel("try"), b.getLabel("end"), b.getLabel("handler"));
        return new MethodContext(new ImmutableMethod("LCalls;", "test", List.of(), "I", 9, Set.of(), Set.of(), b.getMethodImplementation()));
    }
    @Test public void separatesScalarTemporaryButLeavesHandlerLocal() {
        var context = code(false, false); assertEquals(1, HandlerValueRegisters.run(context));
        var g = context.graph(); int fresh = ((OneRegisterInstruction)g.at(3)).getRegisterA();
        assertNotEquals(2, fresh); assertEquals(fresh, ((TwoRegisterInstruction)g.at(4)).getRegisterB());
        assertEquals(2, ((FiveRegisterInstruction)g.at(7)).getRegisterC());
        assertEquals(0, HandlerValueRegisters.run(context));
    }
    @Test public void separatesUnprotectedFieldReadWithoutRemovingIt() {
        var context = code(false, false);
        context.code().replaceInstruction(3, new BuilderInstruction21c(Opcode.SGET, 2, new ImmutableFieldReference("LCalls;", "value", "I")));
        assertEquals(1, HandlerValueRegisters.run(context));
        assertEquals(Opcode.SGET, context.graph().at(3).getOpcode());
        assertNotEquals(2, ((OneRegisterInstruction)context.graph().at(3)).getRegisterA());
    }
    @Test public void protectedDefinitionsStay() { assertEquals(0, HandlerValueRegisters.run(code(true, false))); }
    @Test public void unsupportedLaterReadPreventsPartialRename() { assertEquals(0, HandlerValueRegisters.run(code(false, true))); }
}
