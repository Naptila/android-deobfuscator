package me.naptila.deobfuscator.transformers.np.methodhiding;

import java.util.*;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.immutable.instruction.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class ProxyTraceCopiesTest {
    @Test public void overwrittenSourcesAndWideAliasesKeepTheirValues() {
        List<List<Instruction>> cases = List.of(
                List.of(new ImmutableInstruction12x(Opcode.MOVE, 0, 4), new ImmutableInstruction31i(Opcode.CONST, 4, 7), new ImmutableInstruction11x(Opcode.RETURN, 0)),
                List.of(new ImmutableInstruction12x(Opcode.MOVE, 0, 4), new ImmutableInstruction12x(Opcode.MOVE, 1, 0), new ImmutableInstruction31i(Opcode.CONST, 0, 7), new ImmutableInstruction11x(Opcode.RETURN, 1)),
                List.of(new ImmutableInstruction12x(Opcode.MOVE_WIDE, 0, 4), new ImmutableInstruction12x(Opcode.MOVE_WIDE, 2, 0), new ImmutableInstruction51l(Opcode.CONST_WIDE, 0, 17), new ImmutableInstruction11x(Opcode.RETURN_WIDE, 2)),
                List.of(new ImmutableInstruction12x(Opcode.MOVE_WIDE, 1, 0), new ImmutableInstruction11x(Opcode.RETURN_WIDE, 1)));
        for (var code : cases) for (long value : new long[]{0, -1, Long.MIN_VALUE, Long.MAX_VALUE, 0x12345678abcdef01L})
            assertEquals(evaluate(code, value), evaluate(GuardedProxyTrace.simplifyCopies(code, 6), value));
    }
    private long evaluate(List<Instruction> instructions, long value) {
        int[] words = new int[6]; words[0] = words[4] = (int)value; words[1] = words[5] = (int)(value >>> 32);
        for (var i : instructions) {
            int a = ((OneRegisterInstruction)i).getRegisterA();
            if (i.getOpcode().name.startsWith("move")) {
                int b = ((TwoRegisterInstruction)i).getRegisterB(), low = words[b];
                if (i.getOpcode().name.startsWith("move-wide")) { int high = words[b + 1]; words[a] = low; words[a + 1] = high; }
                else words[a] = low;
            } else if (i.getOpcode() == Opcode.CONST) words[a] = ((NarrowLiteralInstruction)i).getNarrowLiteral();
            else if (i.getOpcode() == Opcode.CONST_WIDE) {
                long n = ((WideLiteralInstruction)i).getWideLiteral(); words[a] = (int)n; words[a + 1] = (int)(n >>> 32);
            } else if (i.getOpcode() == Opcode.RETURN) return words[a];
            else if (i.getOpcode() == Opcode.RETURN_WIDE) return Integer.toUnsignedLong(words[a]) | ((long)words[a + 1] << 32);
            else throw new AssertionError(i.getOpcode());
        }
        throw new AssertionError("missing return");
    }
}
