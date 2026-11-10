package me.naptila.deobfuscator.transformers.np.support;

import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.ConstantEvaluator;
import me.naptila.deobfuscator.dex.Edits;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;

/** Only formats used by the accepted branch-free proxy bodies; no silent truncation. */
/** Register-aware instruction copies shared by method hiding and reflection recovery. */
public final class ProxyInstructions {
    private ProxyInstructions() {}
    public static boolean wide(String type) { return type.equals("J") || type.equals("D"); }
    public static BuilderInstruction move(int dest, int source, String type) {
        Opcode op = ProxyInstructions.wide(type) ? Opcode.MOVE_WIDE_16
                : type.startsWith("L") || type.startsWith("[") ? Opcode.MOVE_OBJECT_16 : Opcode.MOVE_16;
        return new BuilderInstruction32x(op, dest, source);
    }
    public static BuilderInstruction copy(Instruction i, int base) {
        return copy(i, r -> r + base);
    }
    public static BuilderInstruction copy(Instruction i, java.util.function.IntUnaryOperator registers) {
        Opcode op = i.getOpcode();
        int a = i instanceof OneRegisterInstruction one ? registers.applyAsInt(one.getRegisterA()) : 0;
        if (a > 255) return null;
        if (i instanceof VariableRegisterInstruction) {
            int[] args = Arrays.stream(ConstantEvaluator.arguments(i)).map(registers).toArray();
            Reference ref = ((ReferenceInstruction)i).getReference();
            Opcode ordinary = switch (op) {
                case INVOKE_STATIC, INVOKE_STATIC_RANGE -> Opcode.INVOKE_STATIC;
                case INVOKE_VIRTUAL, INVOKE_VIRTUAL_RANGE -> Opcode.INVOKE_VIRTUAL;
                case INVOKE_INTERFACE, INVOKE_INTERFACE_RANGE -> Opcode.INVOKE_INTERFACE;
                case INVOKE_DIRECT, INVOKE_DIRECT_RANGE -> Opcode.INVOKE_DIRECT;
                default -> null;
            };
            if (ordinary == null) return null;
            if (args.length <= 5 && Arrays.stream(args).allMatch(r -> r < 16)) {
                int[] padded = Arrays.copyOf(args, 5);
                return new BuilderInstruction35c(ordinary, args.length, padded[0], padded[1], padded[2], padded[3], padded[4], ref);
            }
            for (int n = 1; n < args.length; n++) if (args[n] != args[0] + n) return null;
            Opcode range = switch (ordinary) {
                case INVOKE_STATIC -> Opcode.INVOKE_STATIC_RANGE;
                case INVOKE_VIRTUAL -> Opcode.INVOKE_VIRTUAL_RANGE;
                case INVOKE_INTERFACE -> Opcode.INVOKE_INTERFACE_RANGE;
                case INVOKE_DIRECT -> Opcode.INVOKE_DIRECT_RANGE;
                default -> throw new IllegalStateException();
            };
            return new BuilderInstruction3rc(range, args.length == 0 ? 0 : args[0], args.length, ref);
        }
        if (op.name.startsWith("const-wide")) return new BuilderInstruction51l(Opcode.CONST_WIDE, a, ((WideLiteralInstruction)i).getWideLiteral());
        if (op.name.startsWith("const") && i instanceof NarrowLiteralInstruction lit) return Edits.constant(a, lit.getNarrowLiteral());
        if (op == Opcode.CONST_STRING || op == Opcode.CONST_STRING_JUMBO)
            return Edits.constant(a, ((StringReference)((ReferenceInstruction)i).getReference()).getString());
        if (i instanceof TwoRegisterInstruction two) {
            int b = registers.applyAsInt(two.getRegisterB());
            if (op.name.startsWith("move")) return move(a, b, op.name.startsWith("move-wide") ? "J" : op.name.startsWith("move-object") ? "Ljava/lang/Object;" : "I");
            if (i instanceof ReferenceInstruction ref && op.format == Format.Format22c && a < 16 && b < 16)
                return new BuilderInstruction22c(op, a, b, ref.getReference());
            return null;
        }
        if (i instanceof ReferenceInstruction ref && op.format == Format.Format21c) return new BuilderInstruction21c(op, a, ref.getReference());
        if (i instanceof OneRegisterInstruction && op.format == Format.Format11x) return new BuilderInstruction11x(op, a);
        if (op == Opcode.NOP || op == Opcode.RETURN_VOID) return new BuilderInstruction10x(op);
        return null;
    }
}
