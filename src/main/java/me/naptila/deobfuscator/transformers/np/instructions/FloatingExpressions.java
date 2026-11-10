package me.naptila.deobfuscator.transformers.np.instructions;

import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.BuilderInstruction;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.instruction.*;

/** Opt-in algebraic recovery of NP float/double expansions, NOT IEEE-equivalent optimization. */
final class FloatingExpressions {
    private FloatingExpressions() {}
    static int restore(MethodContext context) {
        boolean candidate = false;
        for (Instruction i : context.code().getInstructions())
            if (arithmetic(i.getOpcode(), 32) || arithmetic(i.getOpcode(), 64)) { candidate = true; break; }
        if (!candidate) return 0;
        int edits = 0;
        while (rewriteOne(context)) edits++;
        return edits;
    }

    private static boolean rewriteOne(MethodContext context) {
        CodeGraph graph = context.graph();
        RegisterLiveness live = new RegisterLiveness(graph);
        for (int start = 0; start < graph.size(); start++) for (int bits : new int[]{32, 64}) {
            Window window = new Window(graph, start, bits);
            BitSet written = new BitSet();
            List<BuilderInstruction> conversions = new ArrayList<>();
            for (int end = start; end < Math.min(start + 16, graph.size()); end++) {
                if (end != start && graph.leaders().contains(end)) break;
                Instruction instruction = graph.at(end);
                // DEX casts use low registers, often preceded by a move/from16.
                boolean preparation = end + 1 < graph.size() && numericConversion(graph.at(end + 1).getOpcode())
                        && (move(instruction.getOpcode(), 32) || move(instruction.getOpcode(), 64));
                Form form = preparation ? null : window.step(instruction);
                if (form == null && window.independentConversion(instruction)) {
                    TwoRegisterInstruction conversion = (TwoRegisterInstruction) instruction;
                    if (move(instruction.getOpcode(), 32) || move(instruction.getOpcode(), 64))
                        conversions.add(new BuilderInstruction32x(move(instruction.getOpcode(), 64) ? Opcode.MOVE_WIDE_16 : Opcode.MOVE_16,
                                conversion.getRegisterA(), conversion.getRegisterB()));
                    else conversions.add(new BuilderInstruction12x(instruction.getOpcode(), conversion.getRegisterA(), conversion.getRegisterB()));
                    continue;
                }
                if (form == null) break;
                written.or(RegisterLiveness.writes(instruction));
                if (window.operations < 2 || !window.expansionEvidence) continue;
                BitSet auxiliary = (BitSet) written.clone(); auxiliary.andNot(RegisterLiveness.writes(instruction));
                boolean dead = true;
                for (int r = auxiliary.nextSetBit(0); r >= 0; r = auxiliary.nextSetBit(r + 1))
                    dead &= !live.liveAfter(end, r);
                if (!dead) continue;
                int destination = ((OneRegisterInstruction) instruction).getRegisterA();
                List<BuilderInstruction> replacement = emit(form, bits, destination, graph.registers(), live, end);
                if (replacement == null || replacement.size() + conversions.size() >= end - start + 1) continue;
                // Independent, nonthrowing conversions keep their order and run before the
                // replacement. They neither observe nor overwrite any removed computation.
                List<BuilderInstruction> output = new ArrayList<>(conversions); output.addAll(replacement);
                BitSet remove = new BitSet(); remove.set(start + 1, end + 1);
                ExceptionEdits.remove(context, remove);
                Edits.apply(context.code(), List.of(new Edits.Edit(start, false, output)));
                return true;
            }
        }
        return false;
    }

    /** Integer coefficients represent real algebra, never the encoded bits of floating values. */
    private record Form(Map<Integer, Integer> terms, long constant, boolean literalOrigin) {
        static Form variable(int register) { return new Form(Map.of(register, 1), 0, false); }
        static Form literal(long value) { return new Form(Map.of(), value, true); }
        Form combine(Form other, int sign) {
            Map<Integer, Integer> result = new LinkedHashMap<>(terms);
            other.terms.forEach((r, coefficient) -> result.merge(r, sign * coefficient, Integer::sum));
            result.values().removeIf(coefficient -> coefficient == 0);
            return new Form(result, constant + sign * other.constant, false);
        }
    }

    private static final class Window {
        final CodeGraph graph;
        final int start, bits, words;
        final Map<Integer, Form> values = new HashMap<>();
        final BitSet touched = new BitSet();
        final BitSet inputs = new BitSet();
        final BitSet otherWidth = new BitSet();
        int operations;
        boolean expansionEvidence;
        Window(CodeGraph graph, int start, int bits) {
            this.graph = graph; this.start = start; this.bits = bits; words = bits / 32;
        }
        Form read(int register) {
            if (otherWidth.get(register) || words == 2 && otherWidth.get(register + 1)) return null;
            if (values.containsKey(register)) return used(values.get(register));
            if (touched.get(register) || words == 2 && touched.get(register + 1)) return null;
            Form value = literalBefore(graph, start, register, bits);
            if (value == null) value = Form.variable(register);
            values.put(register, value); return used(value);
        }
        Form used(Form form) {
            form.terms.keySet().forEach(r -> inputs.set(r, r + words));
            return form;
        }
        boolean independentConversion(Instruction instruction) {
            Opcode op = instruction.getOpcode();
            boolean moving = move(op, 32) || move(op, 64);
            if (!numericConversion(op) && !moving) return false;
            boolean wide = op == Opcode.INT_TO_DOUBLE || op == Opcode.LONG_TO_DOUBLE || op == Opcode.FLOAT_TO_DOUBLE;
            if (!moving && wide != (bits == 64)) return false;
            BitSet writes = RegisterLiveness.writes(instruction), reads = RegisterLiveness.reads(instruction);
            if (writes.intersects(inputs) || reads.intersects(touched)) return false;
            BitSet overwritten = (BitSet) writes.clone(); overwritten.and(touched);
            // NP reuses a constant's register for the next cast. Constants folded into
            // forms need no register at runtime, so that specific reuse is allowed.
            for (var entry : values.entrySet()) if (entry.getValue().terms.isEmpty())
                overwritten.clear(entry.getKey(), entry.getKey() + words);
            if (!overwritten.isEmpty()) return false;
            touched.andNot(writes);
            otherWidth.andNot(writes);
            values.keySet().removeIf(r -> writes.get(r) || words == 2 && writes.get(r + 1));
            // Don't infer pre-window literals for registers defined by retained conversions.
            int destination = ((OneRegisterInstruction) instruction).getRegisterA();
            if (!moving || move(op, bits)) values.put(destination, Form.variable(destination));
            else otherWidth.or(writes); // wrong-width move can only feed a retained cast
            return true;
        }
        Form step(Instruction instruction) {
            if (!(instruction instanceof OneRegisterInstruction one)) return null;
            Opcode op = instruction.getOpcode();
            Form result = literal(instruction, bits);
            if (result == null && move(op, bits)) result = read(((TwoRegisterInstruction) instruction).getRegisterB());
            else if (result == null && arithmetic(op, bits)) {
                if (op == Opcode.NEG_FLOAT || op == Opcode.NEG_DOUBLE) {
                    Form operand = read(((TwoRegisterInstruction) instruction).getRegisterB());
                    if (operand == null) return null;
                    result = Form.literal(0).combine(operand, -1);
                    expansionEvidence = true;
                } else {
                    int a, b;
                    if (instruction instanceof ThreeRegisterInstruction three) { a = three.getRegisterB(); b = three.getRegisterC(); }
                    else { a = one.getRegisterA(); b = ((TwoRegisterInstruction) instruction).getRegisterB(); }
                    Form left = read(a), right = read(b);
                    if (left == null || right == null) return null;
                    expansionEvidence |= left.literalOrigin || right.literalOrigin;
                    result = left.combine(right, op.name.startsWith("add-") ? 1 : -1);
                }
                operations++;
            }
            if (result == null) return null;
            int destination = one.getRegisterA();
            values.keySet().removeIf(r -> overlap(r, destination, words));
            touched.set(destination, destination + words);
            otherWidth.clear(destination, destination + words);
            values.put(destination, result); return result;
        }
    }

    private static Form literalBefore(CodeGraph graph, int start, int register, int bits) {
        if (graph.leaders().contains(start)) return null;
        BitSet words = new BitSet(); words.set(register, register + bits / 32);
        for (int i = start - 1; i >= 0; i--) {
            Instruction instruction = graph.at(i);
            if (RegisterLiveness.writes(instruction).intersects(words))
                return ((OneRegisterInstruction) instruction).getRegisterA() == register ? literal(instruction, bits) : null;
            if (graph.leaders().contains(i)) break;
        }
        return null;
    }

    private static Form literal(Instruction instruction, int bits) {
        Opcode op = instruction.getOpcode();
        double value;
        if (bits == 32 && (op == Opcode.CONST_4 || op == Opcode.CONST_16 || op == Opcode.CONST || op == Opcode.CONST_HIGH16))
            value = Float.intBitsToFloat(((NarrowLiteralInstruction) instruction).getNarrowLiteral());
        else if (bits == 64 && (op == Opcode.CONST_WIDE_16 || op == Opcode.CONST_WIDE_32 || op == Opcode.CONST_WIDE || op == Opcode.CONST_WIDE_HIGH16))
            value = Double.longBitsToDouble(((WideLiteralInstruction) instruction).getWideLiteral());
        else return null;
        // NP inserts small integral floating constants; do not fold arbitrary FP literals.
        return Double.isFinite(value) && Math.abs(value) <= 64 && value == Math.rint(value) ? Form.literal((long)value) : null;
    }

    private static boolean arithmetic(Opcode op, int bits) {
        return bits == 32 ? op == Opcode.ADD_FLOAT || op == Opcode.SUB_FLOAT || op == Opcode.ADD_FLOAT_2ADDR
                || op == Opcode.SUB_FLOAT_2ADDR || op == Opcode.NEG_FLOAT
                : op == Opcode.ADD_DOUBLE || op == Opcode.SUB_DOUBLE || op == Opcode.ADD_DOUBLE_2ADDR
                || op == Opcode.SUB_DOUBLE_2ADDR || op == Opcode.NEG_DOUBLE;
    }
    private static boolean numericConversion(Opcode op) {
        return op == Opcode.INT_TO_FLOAT || op == Opcode.INT_TO_DOUBLE || op == Opcode.LONG_TO_FLOAT
                || op == Opcode.LONG_TO_DOUBLE || op == Opcode.FLOAT_TO_DOUBLE || op == Opcode.DOUBLE_TO_FLOAT;
    }
    private static boolean move(Opcode op, int bits) {
        return bits == 32 ? op == Opcode.MOVE || op == Opcode.MOVE_FROM16 || op == Opcode.MOVE_16
                : op == Opcode.MOVE_WIDE || op == Opcode.MOVE_WIDE_FROM16 || op == Opcode.MOVE_WIDE_16;
    }
    private static boolean overlap(int a, int b, int words) { return a < b + words && b < a + words; }

    private static List<BuilderInstruction> emit(Form form, int bits, int destination, int registers, RegisterLiveness live, int end) {
        if (form.constant != 0 || form.terms.size() > 2) return null;
        List<Integer> positive = new ArrayList<>(), negative = new ArrayList<>();
        for (var entry : form.terms.entrySet()) {
            if (entry.getValue() == 1) positive.add(entry.getKey());
            else if (entry.getValue() == -1) negative.add(entry.getKey());
            else return null;
        }
        if (form.terms.isEmpty()) return destination <= 255 ? List.of(zero(destination, bits)) : null;
        if (positive.size() == 1 && negative.isEmpty())
            return List.of(new BuilderInstruction32x(bits == 32 ? Opcode.MOVE_16 : Opcode.MOVE_WIDE_16, destination, positive.get(0)));
        if (destination > 255 || form.terms.keySet().stream().anyMatch(r -> r > 255)) return null;
        if (positive.size() == 2)
            return List.of(new BuilderInstruction23x(bits == 32 ? Opcode.ADD_FLOAT : Opcode.ADD_DOUBLE,
                    destination, positive.get(0), positive.get(1)));
        if (positive.size() == 1 && negative.size() == 1)
            return List.of(new BuilderInstruction23x(bits == 32 ? Opcode.SUB_FLOAT : Opcode.SUB_DOUBLE,
                    destination, positive.get(0), negative.get(0)));
        if (!positive.isEmpty() || negative.size() != 1) return null;
        int source = negative.get(0);
        if (destination < 16 && source < 16)
            return List.of(new BuilderInstruction12x(bits == 32 ? Opcode.NEG_FLOAT : Opcode.NEG_DOUBLE, destination, source));
        int words = bits / 32, scratch = -1;
        if (!overlap(destination, source, words)) scratch = destination;
        else for (int r = 0; r + words <= registers && r <= 255; r++) {
            if (overlap(r, source, words) || overlap(r, destination, words)) continue;
            if (!live.liveAfter(end, r) && (words == 1 || !live.liveAfter(end, r + 1))) { scratch = r; break; }
        }
        return scratch < 0 ? null : List.of(zero(scratch, bits),
                new BuilderInstruction23x(bits == 32 ? Opcode.SUB_FLOAT : Opcode.SUB_DOUBLE, destination, scratch, source));
    }
    private static BuilderInstruction zero(int register, int bits) {
        return bits == 32 ? new BuilderInstruction31i(Opcode.CONST, register, 0) : new BuilderInstruction51l(Opcode.CONST_WIDE, register, 0);
    }
}
