package me.naptila.deobfuscator.transformers.np.instructions;

import java.util.*;

import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.transformers.np.NpTransformer;
import me.naptila.deobfuscator.transformers.np.analysis.IntegerExpressions;

import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.AccessFlags;
import org.jf.dexlib2.builder.BuilderInstruction;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.TypeReference;

import static me.naptila.deobfuscator.transformers.np.analysis.IntegerExpressions.*;

/** Recover bounded arithmetic expansions and normalize proven constructor aliases. */
public final class InstructionTransformer extends NpTransformer {
    private final boolean restoreFloatingPoint;
    public InstructionTransformer() { this(false); }
    public InstructionTransformer(boolean restoreFloatingPoint) {
        this.restoreFloatingPoint = restoreFloatingPoint;
    }
    public String id() { return "np.instructions"; }
    public PassResult run(MethodContext context) {
        if (model.helpers().owners().isEmpty() || model.helpers().owners().contains(context.original().getDefiningClass())) return PassResult.unchanged();
        int edits = 0;
        while (rewriteOne(context) || AdditiveOffsets.rewriteOne(context)) edits++;
        int floating = restoreFloatingPoint ? FloatingExpressions.restore(context) : 0;
        int removed = edits + floating == 0 ? 0 : DeadAssignments.remove(context);
        int receivers = constructorReceivers(context);
        int aliases = constructorAliases(context);
        List<String> notes = new ArrayList<>();
        if (edits + floating != 0) notes.add("integer expression windows: " + edits + "; dead assignments: " + removed);
        if (floating != 0) notes.add("floating-point algebraic recovery windows: " + floating
                + "; rounding, signed-zero and NaN behavior may differ");
        if (aliases != 0) notes.add("initialized object aliases normalized: " + aliases);
        if (receivers != 0) notes.add("constructor receiver aliases normalized: " + receivers);
        return new PassResult(edits + floating + removed + aliases + receivers, notes);
    }
    /** Merge repeated copies of an unchanged incoming receiver before constructor branches. */
    private static int constructorReceivers(MethodContext context) {
        if (!context.original().getName().equals("<init>") || AccessFlags.STATIC.isSet(context.original().getAccessFlags())) return 0;
        CodeGraph graph = context.graph();
        int words = 1 + context.original().getParameterTypes().stream()
                .mapToInt(t -> t.toString().equals("J") || t.toString().equals("D") ? 2 : 1).sum();
        int receiver = graph.registers() - words;
        Map<Integer, List<Integer>> copies = new TreeMap<>();
        BitSet otherWrites = new BitSet(), constructorUses = new BitSet();
        for (int i = 0; i < graph.size(); i++) {
            Instruction instruction = graph.at(i); Opcode op = instruction.getOpcode();
            if ((op == Opcode.MOVE_OBJECT || op == Opcode.MOVE_OBJECT_FROM16 || op == Opcode.MOVE_OBJECT_16)
                    && ((TwoRegisterInstruction) instruction).getRegisterB() == receiver
                    && ((TwoRegisterInstruction) instruction).getRegisterA() < receiver) {
                copies.computeIfAbsent(((TwoRegisterInstruction) instruction).getRegisterA(), unused -> new ArrayList<>()).add(i);
            } else otherWrites.or(RegisterLiveness.writes(instruction));
            if ((op == Opcode.INVOKE_DIRECT || op == Opcode.INVOKE_DIRECT_RANGE)
                    && ((ReferenceInstruction) instruction).getReference() instanceof MethodReference method && method.getName().equals("<init>")) {
                int[] args = ConstantEvaluator.arguments(instruction);
                if (args.length > 0) constructorUses.set(args[0]);
            }
        }
        if (otherWrites.get(receiver) || copies.isEmpty()) return 0;
        RegisterLiveness live = new RegisterLiveness(graph);
        BitSet remove = new BitSet(); List<BuilderInstruction> hoisted = new ArrayList<>();
        for (var entry : copies.entrySet()) {
            int alias = entry.getKey();
            // No other definition, incoming value, or handler can observe the alias
            // before its first copy. Every removed assignment writes the same object.
            if (entry.getValue().size() < 2 || otherWrites.get(alias) || live.liveBefore(0, alias) || !constructorUses.get(alias)) continue;
            entry.getValue().forEach(remove::set);
            hoisted.add(new BuilderInstruction32x(Opcode.MOVE_OBJECT_16, alias, receiver));
        }
        if (hoisted.isEmpty()) return 0;
        ExceptionEdits.remove(context, remove);
        Edits.apply(context.code(), List.of(new Edits.Edit(0, true, hoisted)));
        return remove.cardinality();
    }
    private static int constructorAliases(MethodContext context) {
        CodeGraph graph = context.graph();
        Map<Integer, Integer> allocations = new TreeMap<>();
        Map<Integer, String> types = new HashMap<>();
        RegisterLiveness live = null;
        List<Edits.Edit> edits = new ArrayList<>();
        int count = 0;
        for (int i = 0; i < graph.size(); i++) {
            if (graph.leaders().contains(i)) { allocations.clear(); types.clear(); }
            Instruction instruction = graph.at(i); Opcode op = instruction.getOpcode();
            Integer copied = null;
            if (op == Opcode.MOVE_OBJECT || op == Opcode.MOVE_OBJECT_FROM16 || op == Opcode.MOVE_OBJECT_16)
                copied = allocations.get(((TwoRegisterInstruction)instruction).getRegisterB());
            BitSet written = RegisterLiveness.writes(instruction);
            for (int r = written.nextSetBit(0); r >= 0; r = written.nextSetBit(r + 1)) allocations.remove(r);
            if (op == Opcode.NEW_INSTANCE) {
                allocations.put(((OneRegisterInstruction)instruction).getRegisterA(), i);
                types.put(i, ((TypeReference)((ReferenceInstruction)instruction).getReference()).getType());
            } else if (copied != null) {
                allocations.put(((TwoRegisterInstruction)instruction).getRegisterA(), copied);
            } else if ((op == Opcode.INVOKE_DIRECT || op == Opcode.INVOKE_DIRECT_RANGE)
                    && ((ReferenceInstruction)instruction).getReference() instanceof MethodReference method
                    && method.getName().equals("<init>") && method.getReturnType().equals("V")) {
                int[] args = ConstantEvaluator.arguments(instruction);
                if (args.length == 0 || i + 1 >= graph.size()) continue;
                int receiver = args[0]; Integer allocation = allocations.get(receiver);
                if (allocation == null || !method.getDefiningClass().equals(types.get(allocation))) continue;
                List<BuilderInstruction> moves = new ArrayList<>();
                for (var alias : allocations.entrySet()) {
                    int register = alias.getKey();
                    if (!alias.getValue().equals(allocation) || register == receiver) continue;
                    if (live == null) live = new RegisterLiveness(graph);
                    // Only the successful fallthrough matters. Handler liveness would
                    // repeatedly insert copies for aliases used solely on a throwing edge.
                    if (live.liveBefore(i + 1, register))
                        moves.add(new BuilderInstruction32x(Opcode.MOVE_OBJECT_16, register, receiver));
                }
                allocations.values().removeIf(allocation::equals); types.remove(allocation);
                if (!moves.isEmpty()) {
                    // All aliases refer to this exact allocation within one basic block.
                    // Redefine them after initialization so decompilers can merge new/<init>
                    // without retaining uses of the uninitialized SSA value. Existing labels
                    // stay on the next instruction; other incoming edges skip these copies.
                    edits.add(new Edits.Edit(i + 1, true, moves)); count += moves.size();
                }
            }
        }
        Edits.apply(context.code(), edits);
        return count;
    }
    private boolean rewriteOne(MethodContext context) {
        CodeGraph graph = context.graph(); RegisterLiveness live = new RegisterLiveness(graph);
        int[] incomingEdges = AdditiveOffsets.incoming(graph);
        ConstantAnalysis maskFacts = null;
        for (int start = 0; start < graph.size(); start++) {
            if (CodeGraph.isGoto(graph.at(start).getOpcode())) continue;
            int position = start;
            // Expanded XOR masks can be defined before a branch or try handler.
            // Analyze those windows lazily; other arithmetic retains its local proof.
            if (graph.at(start).getOpcode() == Opcode.NOT_INT && maskFacts == null) maskFacts = model.analyze(graph);
            Constants incoming = graph.at(start).getOpcode() == Opcode.NOT_INT ? maskFacts.before(start) : null;
            IntegerExpressions expressions = new IntegerExpressions((register, bits) -> {
                Literal local = literalBefore(graph, position, register, bits);
                return local != null ? local : bits == 32 && incoming != null && incoming.get(register) instanceof Integer value
                        ? new Literal(value, 32) : null;
            });
            BitSet written = new BitSet();
            List<Integer> window = new ArrayList<>(); Set<Integer> seen = new HashSet<>();
            int end = start;
            for (int budget = 0; budget < 64 && window.size() < 12; budget++) {
                if (!seen.add(end)) break;
                Instruction instruction = graph.at(end);
                if (CodeGraph.isGoto(instruction.getOpcode())) {
                    int next = graph.successors(end).get(0);
                    if (incomingEdges[next] != 1) break;
                    end = next; continue;
                }
                Expr result = expressions.step(instruction); if (result == null) break;
                window.add(end);
                written.or(RegisterLiveness.writes(instruction));
                List<Integer> next = graph.successors(end);
                int successor = next.size() == 1 && incomingEdges[next.get(0)] == 1 ? next.get(0) : -1;
                boolean complement = window.size() == 2 && complementPair(graph.at(start), instruction);
                if (window.size() < 2 || expressions.operations() < 2
                        || window.size() == 2 && !negationPair(graph.at(start), instruction) && !complement
                        || expressions.seeded() && expressions.operations() < 3 && !complement) {
                    if (successor < 0) break;
                    end = successor; continue;
                }
                // External masks help recognize expanded identities, but two ordinary
                // arithmetic operations with nearby constants are not sufficient evidence.
                BitSet auxiliary = (BitSet)written.clone(); auxiliary.andNot(RegisterLiveness.writes(instruction));
                boolean dead = true;
                for (int r = auxiliary.nextSetBit(0); r >= 0; r = auxiliary.nextSetBit(r + 1)) dead &= !live.liveAfter(end, r);
                Expr simple = dead ? IntegerExpressions.simplify(result) : null;
                int destination = ((OneRegisterInstruction)instruction).getRegisterA();
                List<BuilderInstruction> replacement = simple == null ? null : emit(simple, destination, graph.registers(), live, end);
                if (replacement != null && replacement.size() < window.size()) {
                    // Only unique normal edges connect this pure window. Keep the
                    // gotos/labels and relocate edits by instruction identity because
                    // later execution can precede start in physical DEX order.
                    BuilderInstruction first = context.code().getInstructions().get(start);
                    BitSet remove = new BitSet();
                    for (int i = 1; i < window.size(); i++) remove.set(window.get(i));
                    ExceptionEdits.remove(context, remove);
                    Edits.apply(context.code(), List.of(new Edits.Edit(first.getLocation().getIndex(), false, replacement)));
                    return true;
                }
                if (successor < 0) break;
                end = successor;
            }
        }
        return false;
    }
    private static boolean negationPair(Instruction first, Instruction second) {
        Opcode a = first.getOpcode(), b = second.getOpcode();
        boolean negated = a == Opcode.NEG_INT || a == Opcode.NEG_LONG
                || (a == Opcode.RSUB_INT || a == Opcode.RSUB_INT_LIT8)
                && ((NarrowLiteralInstruction) first).getNarrowLiteral() == 0;
        return negated && (b == Opcode.SUB_INT || b == Opcode.SUB_INT_2ADDR
                || b == Opcode.SUB_LONG || b == Opcode.SUB_LONG_2ADDR);
    }
    private static boolean complementPair(Instruction first, Instruction second) {
        return first.getOpcode() == Opcode.NOT_INT
                && (second.getOpcode() == Opcode.AND_INT || second.getOpcode() == Opcode.AND_INT_2ADDR)
                || first.getOpcode() == Opcode.NOT_LONG
                && (second.getOpcode() == Opcode.AND_LONG || second.getOpcode() == Opcode.AND_LONG_2ADDR);
    }
    private static Literal literalBefore(CodeGraph graph, int start, int register, int bits) {
        if (graph.leaders().contains(start)) return null;
        BitSet words = new BitSet(); words.set(register, register + bits / 32);
        for (int i = start - 1; i >= 0; i--) {
            Instruction instruction = graph.at(i);
            if (RegisterLiveness.writes(instruction).intersects(words)) {
                if (((OneRegisterInstruction)instruction).getRegisterA() != register) return null;
                Opcode op = instruction.getOpcode();
                if (bits == 64 && (op == Opcode.CONST_WIDE || op == Opcode.CONST_WIDE_16 || op == Opcode.CONST_WIDE_32 || op == Opcode.CONST_WIDE_HIGH16))
                    return new Literal(((WideLiteralInstruction)instruction).getWideLiteral(), 64);
                if (bits == 32 && (op == Opcode.CONST || op == Opcode.CONST_4 || op == Opcode.CONST_16 || op == Opcode.CONST_HIGH16))
                    return new Literal(((NarrowLiteralInstruction)instruction).getNarrowLiteral(), 32);
                return null;
            }
            if (graph.leaders().contains(i)) break;
        }
        return null;
    }
    private static List<BuilderInstruction> emit(Expr expression, int destination, int registers, RegisterLiveness live, int end) {
        int bits = expression.bits(); boolean wide = bits == 64;
        if (expression instanceof Literal literal)
            return destination > 255 ? null : List.of(constant(destination, literal));
        if (expression instanceof Var v)
            return List.of(new BuilderInstruction32x(wide ? Opcode.MOVE_WIDE_16 : Opcode.MOVE_16, destination, v.register()));
        Binary b = (Binary)expression;
        if (destination > 255) return null;
        if (b.left() instanceof Var left && b.right() instanceof Var right) {
            if (left.register() > 255 || right.register() > 255) return null;
            return List.of(new BuilderInstruction23x(opcode(b.op(), bits), destination, left.register(), right.register()));
        }
        Var variable; Literal literal; boolean literalLeft;
        if (b.left() instanceof Var v && b.right() instanceof Literal l) { variable = v; literal = l; literalLeft = false; }
        else if (b.left() instanceof Literal l && b.right() instanceof Var v) { variable = v; literal = l; literalLeft = true; }
        else return null;
        int source = variable.register(); if (source > 255) return null;
        if (b.op().equals("xor") && literal.value() == -1 && destination < 16 && source < 16)
            return List.of(new BuilderInstruction12x(wide ? Opcode.NOT_LONG : Opcode.NOT_INT, destination, source));
        if (!wide) {
            String operation = b.op(); int value = (int)literal.value();
            if (operation.equals("sub")) {
                if (literalLeft) operation = "rsub";
                else { operation = "add"; value = -value; }
            }
            if (value >= -128 && value <= 127)
                return List.of(new BuilderInstruction22b(Opcode.valueOf(operation.toUpperCase(Locale.ROOT) + "_INT_LIT8"), destination, source, value));
            if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE && destination < 16 && source < 16) {
                String name = operation.equals("rsub") ? "RSUB_INT" : operation.toUpperCase(Locale.ROOT) + "_INT_LIT16";
                return List.of(new BuilderInstruction22s(Opcode.valueOf(name), destination, source, value));
            }
        }
        int words = bits / 32, scratch = -1;
        if (!overlap(destination, source, words)) scratch = destination;
        else for (int r = 0; r + words <= registers && r <= 255; r++) {
            if (overlap(r, source, words) || overlap(r, destination, words)) continue;
            if (!live.liveAfter(end, r) && (!wide || !live.liveAfter(end, r + 1))) { scratch = r; break; }
        }
        if (scratch < 0) return null;
        return List.of(constant(scratch, literal), new BuilderInstruction23x(opcode(b.op(), bits), destination,
                literalLeft ? scratch : source, literalLeft ? source : scratch));
    }
    private static boolean overlap(int a, int b, int words) { return a < b + words && b < a + words; }
    private static Opcode opcode(String op, int bits) { return Opcode.valueOf(op.toUpperCase(Locale.ROOT) + (bits == 64 ? "_LONG" : "_INT")); }
    private static BuilderInstruction constant(int register, Literal literal) {
        return literal.bits() == 64 ? new BuilderInstruction51l(Opcode.CONST_WIDE, register, literal.value())
                : new BuilderInstruction31i(Opcode.CONST, register, (int)literal.value());
    }

    public static final class Provider extends NpTransformer.Provider {
        public String id() { return "np.instructions"; }
        public String displayName() { return "Instruction simplification"; }
        public String description() { return "Simplify int/long arithmetic and normalize constructor aliases. Floating-point recovery is opt-in."; }
        public DexPass create(TransformerOptions options) {
            options.requireOnly("restoreFloatingPoint");
            return new InstructionTransformer(options.bool("restoreFloatingPoint"));
        }
    }
}
