package me.naptila.deobfuscator.dex;

import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;

/** Small, non-executing DEX interpreter. Unknown instructions invalidate their outputs. */
public final class ConstantEvaluator {
    private ConstantEvaluator() {}
    public static int[] arguments(Instruction instruction) {
        if (instruction instanceof FiveRegisterInstruction f) {
            int[] all = {f.getRegisterC(), f.getRegisterD(), f.getRegisterE(), f.getRegisterF(), f.getRegisterG()};
            return java.util.Arrays.copyOf(all, f.getRegisterCount());
        }
        if (instruction instanceof RegisterRangeInstruction r) {
            return java.util.stream.IntStream.range(r.getStartRegister(), r.getStartRegister() + r.getRegisterCount()).toArray();
        }
        return new int[0];
    }
    public static boolean isStringHash(Instruction instruction) {
        Opcode op = instruction.getOpcode();
        return (op == Opcode.INVOKE_VIRTUAL || op == Opcode.INVOKE_VIRTUAL_RANGE)
                && instruction instanceof ReferenceInstruction ref && ref.getReference() instanceof MethodReference method
                && Signatures.of(method).equals("Ljava/lang/String;->hashCode()I") && arguments(instruction).length == 1;
    }
    /** Returns true only for fully understood, side-effect-free instructions with known outputs. */
    public static boolean step(Instruction instruction, Constants state) {
        Opcode op = instruction.getOpcode();
        Object pending = state.result(); state.result(null);
        if (op == Opcode.NOP) return true;
        if (isStringHash(instruction)) {
            Object receiver = state.get(arguments(instruction)[0]);
            if (receiver instanceof String s) { state.result(s.hashCode()); return true; }
            return false;
        }
        Object value = null;
        boolean understood = true;
        switch (op) {
            case CONST_4, CONST_16, CONST, CONST_HIGH16 -> value = ((NarrowLiteralInstruction) instruction).getNarrowLiteral();
            case CONST_STRING, CONST_STRING_JUMBO -> value = ((StringReference) ((ReferenceInstruction) instruction).getReference()).getString();
            case MOVE, MOVE_FROM16, MOVE_16, MOVE_OBJECT, MOVE_OBJECT_FROM16, MOVE_OBJECT_16 ->
                value = state.get(((TwoRegisterInstruction) instruction).getRegisterB());
            case MOVE_RESULT, MOVE_RESULT_OBJECT -> value = pending;
            case CHECK_CAST -> {
                // Preserve a literal through the String casts introduced by proxy expansion.
                // The instruction and its exception edges remain in the method.
                Object operand = state.get(((OneRegisterInstruction) instruction).getRegisterA());
                if (operand instanceof String && ((TypeReference) ((ReferenceInstruction) instruction).getReference())
                        .getType().equals("Ljava/lang/String;")) value = operand;
            }
            case NEG_INT, NOT_INT -> {
                Object operand = state.get(((TwoRegisterInstruction) instruction).getRegisterB());
                if (operand instanceof Integer n) value = op == Opcode.NEG_INT ? -n : ~n;
            }
            default -> {
                String name = op.name;
                if (name.startsWith("xor-int") || name.startsWith("add-int") || name.startsWith("sub-int")
                        || name.startsWith("rsub-int") || name.startsWith("and-int") || name.startsWith("or-int")
                        || name.startsWith("mul-int") || name.startsWith("div-int") || name.startsWith("rem-int")
                        || name.startsWith("shl-int") || name.startsWith("shr-int") || name.startsWith("ushr-int")) {
                    int leftRegister; Object right;
                    if (instruction instanceof ThreeRegisterInstruction three) {
                        leftRegister = three.getRegisterB(); right = state.get(three.getRegisterC());
                    } else if (instruction instanceof NarrowLiteralInstruction literal && instruction instanceof TwoRegisterInstruction two) {
                        leftRegister = two.getRegisterB(); right = literal.getNarrowLiteral();
                    } else if (name.endsWith("/2addr") && instruction instanceof TwoRegisterInstruction two) {
                        leftRegister = two.getRegisterA(); right = state.get(two.getRegisterB());
                    } else { leftRegister = -1; right = null; }
                    Object left = state.get(leftRegister);
                    if (left instanceof Integer a && right instanceof Integer b) {
                        if (name.startsWith("xor-")) value = a ^ b;
                        else if (name.startsWith("add-")) value = a + b;
                        else if (name.startsWith("sub-")) value = a - b;
                        else if (name.startsWith("rsub-")) value = b - a;
                        else if (name.startsWith("and-")) value = a & b;
                        else if (name.startsWith("or-")) value = a | b;
                        else if (name.startsWith("mul-")) value = a * b;
                        else if (name.startsWith("div-")) { if (b != 0) value = a / b; }
                        else if (name.startsWith("rem-")) { if (b != 0) value = a % b; }
                        else if (name.startsWith("shl-")) value = a << b;
                        else if (name.startsWith("shr-")) value = a >> b;
                        else value = a >>> b;
                    }
                } else understood = false;
            }
        }
        if (op.setsRegister() && instruction instanceof OneRegisterInstruction one) {
            state.put(one.getRegisterA(), value);
            if (op.setsWideRegister()) state.put(one.getRegisterA() + 1, null);
        }
        return understood && value != null;
    }
}
