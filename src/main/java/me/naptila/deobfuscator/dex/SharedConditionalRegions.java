package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.MethodReference;

/** Give a boolean call's taken edge its own bounded region, retaining every executed operation. */
public final class SharedConditionalRegions {
    private SharedConditionalRegions() {}
    public static int run(MethodContext context) {
        return run(context, false);
    }
    /** Terminal tails are specialized only for methods with direct NP evidence. */
    public static int run(MethodContext context, boolean terminalTails) {
        if (!context.code().getTryBlocks().isEmpty()) return protectedBooleanLiteral(context);
        CodeGraph graph = context.graph(); int size = graph.size();
        if (size == 0 || size > 1024) return 0;
        BitSet reachable = new BitSet(); ArrayDeque<Integer> work = new ArrayDeque<>(); work.add(0);
        while (!work.isEmpty()) {
            int at = work.removeFirst(); if (reachable.get(at)) continue;
            reachable.set(at); work.addAll(graph.successors(at));
        }
        if (graph.at(size - 1).getOpcode().canContinue()) {
            // Removed switch payloads may leave alignment NOPs after an unconditional
            // transfer. Appending cloned regions is safe only if that tail cannot execute.
            if (reachable.get(size - 1)) return 0;
        }
        for (int i = 0; i < size; i++) if (graph.isPayload(i)) return 0;
        List<Set<Integer>> predecessors = new ArrayList<>();
        for (int i = 0; i < size; i++) predecessors.add(new HashSet<>());
        // Unreachable alignment NOPs can fall through to a region without giving
        // it another executable entry. Counting them repeatedly clones the same
        // region after unreachable cleanup removes the previous copy.
        for (int i = reachable.nextSetBit(0); i >= 0; i = reachable.nextSetBit(i + 1))
            for (int next : graph.successors(i)) predecessors.get(next).add(i);
        BitSet[] post = null;
        for (int source = 0; source + 1 < size; source++) {
            if (!reachable.get(source)) continue;
            Instruction instruction = graph.at(source); Opcode op = instruction.getOpcode();
            if (op != Opcode.IF_EQZ && op != Opcode.IF_NEZ) continue;
            boolean booleanCall = source >= 2 && graph.at(source - 1).getOpcode() == Opcode.MOVE_RESULT
                    && ((OneRegisterInstruction)instruction).getRegisterA() == ((OneRegisterInstruction)graph.at(source - 1)).getRegisterA()
                    && graph.at(source - 2) instanceof ReferenceInstruction reference
                    && reference.getReference() instanceof MethodReference method && method.getReturnType().equals("Z");
            int target = graph.successors(source).get(0);
            Opcode head = graph.at(target).getOpcode();
            if (target == source + 1 || predecessors.get(target).size() < 2
                    || !(CodeGraph.isIf(head) || integerConstant(head) || copy(head))) continue;
            Set<Integer> region = new TreeSet<>(), exits = new HashSet<>();
            int provenRegister = -1;
            if (booleanCall && size <= 512) {
                if (post == null) post = postdominators(graph);
                if (post == null) return 0;
                BitSet common = (BitSet)post[target].clone(); common.and(post[source + 1]); common.clear(size);
                int join = -1, depth = -1;
                for (int i = common.nextSetBit(0); i >= 0; i = common.nextSetBit(i + 1))
                    if (post[i].cardinality() > depth) { join = i; depth = post[i].cardinality(); }
                if (join >= 0 && join != target && !isResult(graph.at(join).getOpcode())
                        && collect(graph, target, join, region, new HashSet<>())) exits.add(join);
                else region.clear();
            }
            if (region.isEmpty()) {
                int register = ((OneRegisterInstruction)instruction).getRegisterA();
                // A shared null-coalescing prefix can repeat the edge's test,
                // then exit to different business paths instead of one join.
                // Require the same unchanged register and specialize that test;
                // copying an arbitrary prefix can create new sharing forever.
                if ((head != Opcode.IF_EQZ && head != Opcode.IF_NEZ)
                        || ((OneRegisterInstruction)graph.at(target)).getRegisterA() != register
                        || !transparentPrefix(graph, target, region, exits, new HashSet<>())
                        || region.stream().noneMatch(i -> graph.at(i).getOpcode().name.startsWith("move-object"))
                        || region.stream().anyMatch(i -> RegisterLiveness.writes(graph.at(i)).get(register))) continue;
                provenRegister = register;
            }
            if (region.contains(source) || region.contains(source + 1)) continue;
            int originalSize = context.originalGraph().size();
            if (size + region.size() * 2 > originalSize + 128) continue;
            cloneEdge(context, graph, source, target, exits, region, provenRegister);
            return 1;
        }
        int arrays = runArrayPrefixes(context);
        if (arrays != 0) return arrays;
        return terminalTails ? terminalTail(context, graph, reachable, predecessors) : 0;
    }
    /** Give a shared, straight-line array initialization its own conditional entry. */
    public static int runArrayPrefixes(MethodContext context) {
        if (!context.code().getTryBlocks().isEmpty() || context.code().getDebugItems().iterator().hasNext()) return 0;
        CodeGraph graph = context.graph(); int size = graph.size();
        if (size == 0 || size > 1024) return 0;
        boolean allocation = false;
        for (int i = 0; i < size; i++) allocation |= arrayAllocation(graph.at(i).getOpcode());
        if (!allocation) return 0;
        BitSet reachable = new BitSet(); ArrayDeque<Integer> work = new ArrayDeque<>(); work.add(0);
        List<Set<Integer>> previous = new ArrayList<>();
        for (int i = 0; i < size; i++) previous.add(new HashSet<>());
        while (!work.isEmpty()) {
            int at = work.removeFirst(); if (reachable.get(at)) continue;
            reachable.set(at);
            for (int next : graph.successors(at)) { previous.get(next).add(at); work.add(next); }
        }
        if (graph.at(size - 1).getOpcode().canContinue() && reachable.get(size - 1)) return 0;
        BitSet[] post = postdominators(graph); if (post == null) return 0;
        for (int source = 0; source + 1 < size; source++) {
            if (!reachable.get(source) || !CodeGraph.isIf(graph.at(source).getOpcode())) continue;
            int target = graph.successors(source).get(0);
            BitSet common = (BitSet)post[target].clone(); common.and(post[source + 1]); common.clear(size);
            int join = -1, depth = -1;
            for (int at = common.nextSetBit(0); at >= 0; at = common.nextSetBit(at + 1))
                if (post[at].cardinality() > depth) { join = at; depth = post[at].cardinality(); }
            if (join < 0 || join == target || isResult(graph.at(join).getOpcode())) continue;
            Set<Integer> region = new TreeSet<>();
            if (!collect(graph, target, join, region, new HashSet<>()) || region.contains(source) || region.contains(source + 1)
                    || size + region.size() * 2 > 1024 || size + region.size() * 2 > context.originalGraph().size() + 128) continue;
            int arrays = 0; boolean shared = false, allowed = true;
            for (int at : region) {
                Opcode op = graph.at(at).getOpcode();
                arrays += arrayAllocation(op) ? 1 : 0;
                shared |= previous.get(at).size() > 1;
                allowed &= op == Opcode.NOP || integerConstant(op) || copy(op) || CodeGraph.isGoto(op)
                        || arrayAllocation(op) || op == Opcode.MOVE_RESULT_OBJECT;
                if (op == Opcode.MOVE_RESULT_OBJECT)
                    allowed &= region.contains(at - 1) && (graph.at(at - 1).getOpcode() == Opcode.FILLED_NEW_ARRAY
                            || graph.at(at - 1).getOpcode() == Opcode.FILLED_NEW_ARRAY_RANGE);
            }
            if (!allowed || !shared || arrays != 1) continue;
            cloneEdge(context, graph, source, target, Set.of(join), region, -1);
            return 1;
        }
        return 0;
    }
    private static boolean arrayAllocation(Opcode op) {
        return op == Opcode.NEW_ARRAY || op == Opcode.FILLED_NEW_ARRAY || op == Opcode.FILLED_NEW_ARRAY_RANGE;
    }
    /** Separate a shared boolean literal in place; every throwing instruction stays put. */
    private static int protectedBooleanLiteral(MethodContext context) {
        CodeGraph graph = context.graph(); int size = graph.size();
        if (size > 1024 || size + 2 > context.originalGraph().size() + 128) return 0;
        int[] incoming = new int[size];
        for (int i = 0; i < size; i++) for (int next : graph.successors(i)) incoming[next]++;
        for (int source = 2; source + 2 < size; source++) {
            Opcode op = graph.at(source).getOpcode();
            if ((op != Opcode.IF_EQZ && op != Opcode.IF_NEZ) || graph.protection(source).isEmpty()
                    || graph.at(source - 1).getOpcode() != Opcode.MOVE_RESULT
                    || ((OneRegisterInstruction)graph.at(source - 1)).getRegisterA() != ((OneRegisterInstruction)graph.at(source)).getRegisterA()
                    || !graph.at(source - 2).getOpcode().name.startsWith("invoke-")
                    || !(graph.at(source - 2) instanceof ReferenceInstruction reference)
                    || !(reference.getReference() instanceof MethodReference method) || !method.getReturnType().equals("Z")) continue;
            int target = graph.successors(source).get(0);
            if (target <= source + 2 || target + 1 >= size || incoming[target] < 2
                    || !CodeGraph.isGoto(graph.at(source + 2).getOpcode())
                    || graph.successors(source + 2).get(0) != target + 1
                    || !integerConstant(graph.at(source + 1).getOpcode()) || !integerConstant(graph.at(target).getOpcode())) continue;
            int left = ((NarrowLiteralInstruction)graph.at(source + 1)).getNarrowLiteral();
            int right = ((NarrowLiteralInstruction)graph.at(target)).getNarrowLiteral();
            if (left < 0 || left > 1 || right < 0 || right > 1 || left == right
                    || ((OneRegisterInstruction)graph.at(source + 1)).getRegisterA() != ((OneRegisterInstruction)graph.at(target)).getRegisterA()) continue;
            boolean same = true;
            for (int at : new int[]{source + 1, source + 2, target, target + 1})
                same &= graph.protection(source).equals(graph.protection(at));
            if (!same) continue;
            var code = context.code();
            Label next = code.newLabelForIndex(source + 1), join = code.newLabelForIndex(target + 1);
            var branch = new BuilderInstruction21t(op == Opcode.IF_EQZ ? Opcode.IF_NEZ : Opcode.IF_EQZ,
                    ((OneRegisterInstruction)graph.at(source)).getRegisterA(), next);
            Edits.apply(code, List.of(new Edits.Edit(source, false, List.of(branch,
                    Edits.copy(graph.at(target), graph.registers()), new BuilderInstruction30t(Opcode.GOTO_32, join)))));
            return 1;
        }
        return 0;
    }
    private static int terminalTail(MethodContext context, CodeGraph graph, BitSet reachable, List<Set<Integer>> predecessors) {
        for (int source = 0; source + 1 < graph.size(); source++) {
            if (!reachable.get(source) || !CodeGraph.isIf(graph.at(source).getOpcode())) continue;
            int target = graph.successors(source).get(0);
            if (target == source + 1 || predecessors.get(target).size() < 2 || isResult(graph.at(target).getOpcode())) continue;
            Set<Integer> region = new TreeSet<>();
            if (!collectTerminal(graph, target, region, new HashSet<>()) || region.contains(source) || region.contains(source + 1)
                    || region.stream().noneMatch(i -> CodeGraph.isIf(graph.at(i).getOpcode()))
                    || graph.size() + region.size() * 2 > 1024) continue;
            // A terminal tree adds no new shared tests. Internal joins may only
            // finish a return/throw path, never lead into another condition.
            boolean sharedTest = false;
            for (int i : region) if (i != target && predecessors.get(i).size() > 1
                    && conditionBelow(graph, i, new HashSet<>())) { sharedTest = true; break; }
            if (sharedTest) continue;
            cloneEdge(context, graph, source, target, Set.of(), region, -1);
            return 1;
        }
        return 0;
    }
    private static boolean collectTerminal(CodeGraph graph, int at, Set<Integer> region, Set<Integer> active) {
        if (active.contains(at)) return false;
        if (region.contains(at)) return true;
        Opcode op = graph.at(at).getOpcode();
        if (region.size() >= 256 || graph.isPayload(at) || CodeGraph.isSwitch(op) || op == Opcode.FILL_ARRAY_DATA
                || op == Opcode.MOVE_EXCEPTION || op == Opcode.MONITOR_ENTER || op == Opcode.MONITOR_EXIT) return false;
        region.add(at); active.add(at);
        if (graph.successors(at).isEmpty() && !(op.name.startsWith("return") || op == Opcode.THROW)) return false;
        for (int next : graph.successors(at)) if (!collectTerminal(graph, next, region, active)) return false;
        active.remove(at); return true;
    }
    private static boolean conditionBelow(CodeGraph graph, int at, Set<Integer> seen) {
        if (!seen.add(at)) return false;
        if (CodeGraph.isIf(graph.at(at).getOpcode())) return true;
        for (int next : graph.successors(at)) if (conditionBelow(graph, next, seen)) return true;
        return false;
    }
    private static boolean integerConstant(Opcode op) {
        return op == Opcode.CONST || op == Opcode.CONST_4 || op == Opcode.CONST_16 || op == Opcode.CONST_HIGH16;
    }
    private static boolean copy(Opcode op) { return op.name.startsWith("move") && !isResult(op); }
    private static boolean transparentPrefix(CodeGraph graph, int at, Set<Integer> region, Set<Integer> exits, Set<Integer> active) {
        Opcode op = graph.at(at).getOpcode();
        if (!(op == Opcode.NOP || integerConstant(op) || copy(op) || CodeGraph.isIf(op) || CodeGraph.isGoto(op))) {
            exits.add(at); return true;
        }
        if (active.contains(at)) return false;
        if (region.contains(at)) return true;
        if (region.size() >= 24 || graph.successors(at).isEmpty()) return false;
        region.add(at); active.add(at);
        for (int next : graph.successors(at)) if (!transparentPrefix(graph, next, region, exits, active)) return false;
        active.remove(at); return true;
    }
    private static boolean isResult(Opcode op) {
        return op == Opcode.MOVE_RESULT || op == Opcode.MOVE_RESULT_OBJECT || op == Opcode.MOVE_RESULT_WIDE || op == Opcode.MOVE_EXCEPTION;
    }
    private static boolean collect(CodeGraph graph, int at, int join, Set<Integer> region, Set<Integer> active) {
        if (at == join) return true;
        if (active.contains(at)) return false;
        if (region.contains(at)) return true;
        if (region.size() >= 24 || graph.successors(at).isEmpty() || CodeGraph.isSwitch(graph.at(at).getOpcode())
                || graph.at(at).getOpcode() == Opcode.FILL_ARRAY_DATA || graph.at(at).getOpcode() == Opcode.MOVE_EXCEPTION
                || graph.at(at).getOpcode() == Opcode.NEW_INSTANCE
                || graph.at(at).getOpcode() == Opcode.MONITOR_ENTER || graph.at(at).getOpcode() == Opcode.MONITOR_EXIT) return false;
        region.add(at); active.add(at);
        for (int next : graph.successors(at)) if (!collect(graph, next, join, region, active)) return false;
        active.remove(at); return true;
    }
    private static BitSet[] postdominators(CodeGraph graph) {
        int size = graph.size(); BitSet[] post = new BitSet[size + 1];
        for (int i = 0; i <= size; i++) { post[i] = new BitSet(); post[i].set(0, size + 1); }
        post[size].clear(); post[size].set(size);
        for (int round = 0; round <= size; round++) {
            boolean changed = false;
            for (int i = size - 1; i >= 0; i--) {
                BitSet next = new BitSet(); next.set(0, size + 1);
                List<Integer> successors = graph.successors(i);
                if (successors.isEmpty()) next.and(post[size]);
                else for (int target : successors) next.and(post[target]);
                next.set(i);
                if (!next.equals(post[i])) { post[i] = next; changed = true; }
            }
            if (!changed) return post;
        }
        return null;
    }
    private static void cloneEdge(MethodContext context, CodeGraph graph, int source, int target, Set<Integer> exits, Set<Integer> region, int provenRegister) {
        var code = context.code(); List<Integer> order = new ArrayList<>(region);
        Map<Integer, Integer> slots = new HashMap<>(); Set<Integer> jumps = new HashSet<>(); int size = graph.size();
        for (int k = 0; k < order.size(); k++) {
            int old = order.get(k); slots.put(old, size++);
            if (graph.at(old).getOpcode().canContinue() && (k + 1 == order.size() || order.get(k + 1) != old + 1)) { jumps.add(old); size++; }
        }
        for (int i = graph.size(); i < size; i++) code.addInstruction(new BuilderInstruction10x(Opcode.NOP));
        Map<Integer, Label> labels = new HashMap<>();
        for (int exit : exits) labels.put(exit, code.newLabelForIndex(exit));
        for (int old : order) labels.put(old, code.newLabelForIndex(slots.get(old)));
        for (int old : order) {
            Instruction instruction = graph.at(old); Opcode op = instruction.getOpcode(); BuilderInstruction copy;
            if (CodeGraph.isGoto(op)) copy = new BuilderInstruction30t(Opcode.GOTO_32, labels.get(graph.successors(old).get(0)));
            else if ((op == Opcode.IF_EQZ || op == Opcode.IF_NEZ)
                    && ((OneRegisterInstruction)instruction).getRegisterA() == provenRegister) {
                boolean taken = op == graph.at(source).getOpcode();
                copy = new BuilderInstruction30t(Opcode.GOTO_32, labels.get(graph.successors(old).get(taken ? 0 : 1)));
            } else if (CodeGraph.isIf(op)) {
                Label destination = labels.get(graph.successors(old).get(0));
                copy = instruction instanceof TwoRegisterInstruction r
                        ? new BuilderInstruction22t(op, r.getRegisterA(), r.getRegisterB(), destination)
                        : new BuilderInstruction21t(op, ((OneRegisterInstruction)instruction).getRegisterA(), destination);
            } else copy = Edits.copy(instruction, graph.registers());
            code.replaceInstruction(slots.get(old), copy);
            if (jumps.contains(old)) code.replaceInstruction(slots.get(old) + 1, new BuilderInstruction30t(Opcode.GOTO_32, labels.get(old + 1)));
        }
        Instruction edge = graph.at(source);
        code.replaceInstruction(source, edge instanceof TwoRegisterInstruction r
                ? new BuilderInstruction22t(edge.getOpcode(), r.getRegisterA(), r.getRegisterB(), labels.get(target))
                : new BuilderInstruction21t(edge.getOpcode(), ((OneRegisterInstruction)edge).getRegisterA(), labels.get(target)));
    }
}
