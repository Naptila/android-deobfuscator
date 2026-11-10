package me.naptila.deobfuscator.transformers.np.analysis;

import java.util.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class NpDecoderShapeTest {
    static Method decoder(String defect) {
        var b = new MethodImplementationBuilder(10); // Parameters: v6 table, v7 start, v8 length, v9 key.
        b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 0, 8, new ImmutableTypeReference("[C")));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 2, 0));
        b.addInstruction(new BuilderInstruction30t(Opcode.GOTO_32, b.getLabel("test")));
        b.addLabel("exit");
        b.addInstruction(new BuilderInstruction21c(Opcode.NEW_INSTANCE, 6, new ImmutableTypeReference("Ljava/lang/String;")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_DIRECT, 2, 6, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/String;", "<init>", List.of("[C"), "V")));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 6));
        b.addLabel("body");
        b.addInstruction(new BuilderInstruction22b(Opcode.RSUB_INT_LIT8, 3, 7, 0));
        b.addInstruction(new BuilderInstruction23x(Opcode.SUB_INT, 3, 2, 3));
        b.addInstruction(new BuilderInstruction23x(Opcode.AGET_SHORT, 3, 6, defect.equals("offset") ? 2 : 3));
        b.addInstruction(new BuilderInstruction23x(defect.equals("add") ? Opcode.ADD_INT : Opcode.XOR_INT, 3, 3, 9));
        b.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_CHAR, 3, 3));
        b.addInstruction(new BuilderInstruction23x(Opcode.APUT_CHAR, 3, 0, 2));
        if (defect.equals("effect")) b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Lprobe/Effects;", "run", List.of(), "V")));
        if (defect.equals("write")) b.addInstruction(new BuilderInstruction23x(Opcode.APUT_SHORT, 3, 6, 2));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 3, defect.equals("step") ? 2 : 1));
        b.addInstruction(new BuilderInstruction12x(Opcode.ADD_INT_2ADDR, 3, 2));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 2, 3));
        if (defect.equals("key")) b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 9, 0));
        b.addLabel("test"); b.addInstruction(new BuilderInstruction22t(Opcode.IF_GE, 2, 8, b.getLabel("exit")));
        b.addInstruction(new BuilderInstruction30t(Opcode.GOTO_32, b.getLabel("body")));
        return new ImmutableMethod("Lproof/Helper;", "decode", List.of("[S", "I", "I", "I").stream()
                .map(t -> new ImmutableMethodParameter(t, Set.of(), null)).toList(), "Ljava/lang/String;", 9,
                Set.of(), Set.of(), b.getMethodImplementation());
    }
    @Test public void provesLoopAcrossGotosAndArithmeticCopies() { assertTrue(NpDecoderShape.matches(decoder(""))); }
    @Test public void rejectsWrongAlgorithmMutationSideEffectsAndBrokenInvariants() {
        for (String defect : List.of("offset", "add", "step", "key", "effect", "write"))
            assertFalse(defect, NpDecoderShape.matches(decoder(defect)));
    }
}
