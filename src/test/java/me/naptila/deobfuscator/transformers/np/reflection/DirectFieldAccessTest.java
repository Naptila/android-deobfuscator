package me.naptila.deobfuscator.transformers.np.reflection;

import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class DirectFieldAccessTest {
    final FieldReference field = new ImmutableFieldReference("LOwner;", "value", "J");
    final MethodReference getter = ReflectionCode.ref("LOwner;", "generated", List.of("LOwner;"), "J");
    DexContext dex() {
        Field f = new ImmutableField("LOwner;", "value", "J", AccessFlags.PRIVATE.getValue() | AccessFlags.VOLATILE.getValue(), null, Set.of(), Set.of());
        return new DexContext(new ImmutableDexFile(Opcodes.getDefault(), List.of(new ImmutableClassDef("LOwner;", 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(f), List.of()))));
    }
    MethodContext method(String owner, boolean high) {
        var b = new MethodImplementationBuilder(high ? 22 : 3); int receiver = high ? 21 : 2;
        b.addInstruction(new BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, receiver, 1, getter));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_WIDE, high ? 18 : 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, high ? 18 : 0));
        return new MethodContext(dex(), new ImmutableMethod(owner, "read", List.of(new ImmutableMethodParameter("LOwner;", Set.of(), null)), "J", 9, Set.of(), Set.of(), b.getMethodImplementation()));
    }
    int run(MethodContext c, Map<String, FieldReference> proven) { return DirectReflectionCalls.fields(c, new MemberResolver(c.dex(), new LibraryTypes(List.of())), proven); }
    @Test public void legalPrivateVolatileReadBecomesAFieldInstruction() {
        var c = method("LOwner;", false); assertEquals(1, run(c, Map.of(Signatures.of(getter), field)));
        assertEquals(Opcode.IGET_WIDE, c.graph().at(0).getOpcode()); assertEquals(2, c.graph().size());
        assertTrue(AccessFlags.PRIVATE.isSet(c.dex().fields().get(Signatures.of(field)).getAccessFlags()));
        assertTrue(AccessFlags.VOLATILE.isSet(c.dex().fields().get(Signatures.of(field)).getAccessFlags()));
    }
    @Test public void crossClassPrivateAccessKeepsTheLegalBridge() {
        var c = method("LOther;", false); assertEquals(0, run(c, Map.of(Signatures.of(getter), field)));
        assertEquals(Opcode.INVOKE_STATIC_RANGE, c.graph().at(0).getOpcode());
    }
    @Test public void highRegistersUseAnAvailableLowTemporaryForWideRead() {
        var c = method("LOwner;", true); assertEquals(1, run(c, Map.of(Signatures.of(getter), field)));
        assertEquals(Opcode.MOVE_OBJECT_16, c.graph().at(0).getOpcode()); assertEquals(Opcode.IGET_WIDE, c.graph().at(1).getOpcode());
        assertEquals(Opcode.MOVE_WIDE_16, c.graph().at(2).getOpcode());
        assertEquals(18, ((OneRegisterInstruction)c.graph().at(2)).getRegisterA());
    }
    @Test public void namesAloneNeverAuthorizeInlining() { var c = method("LOwner;", false); assertEquals(0, run(c, Map.of())); }
}
