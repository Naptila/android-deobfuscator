package me.naptila.deobfuscator.transformers.np.reflection;

import java.util.*;

import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.transformers.np.support.ProxyAccess;
import me.naptila.deobfuscator.transformers.np.support.ProxyInstructions;

import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;

/** Scalarizes private straight-line argument arrays, retaining argument evaluation order. */
final class DirectReflectionCalls {
    interface AccessorFactory { MethodReference get(Reference member, MemberResolver.Member resolved, String caller); }
    record Capture(int at, int source, String type, int word) {}
    record Plan(int at, int start, MethodReference target, Opcode opcode,
                int receiver, List<Capture> captures, int words, Set<Integer> remove) {}
    record Slot(int start, int end, int base, int count) {}
    private final ReflectionModel model;
    private final MemberResolver resolver;
    private final AccessorFactory accessors;
    DirectReflectionCalls(ReflectionModel model, MemberResolver resolver, AccessorFactory accessors) { this.model = model; this.resolver = resolver; this.accessors = accessors; }
    int run(MethodContext context) {
        CodeGraph g = context.graph(); if (g.size() == 0) return 0;
        boolean hasCalls = false;
        for (int i = 0; i < g.size(); i++) if (dispatcher(g.at(i)) != null) { hasCalls = true; break; }
        if (!hasCalls) return 0;
        ConstantAnalysis constants = new ConstantAnalysis(g, ConstantEvaluator::step, false, true);
        ReflectionTypes types = new ReflectionTypes(context.original(), g); RegisterLiveness live = new RegisterLiveness(g);
        int[] predecessors = new int[g.size()];
        for (int i = 0; i < g.size(); i++) { for (int n : g.successors(i)) predecessors[n]++; for (int n : g.handlers(i)) predecessors[n]++; }
        List<Plan> plans = new ArrayList<>();
        for (int i = 0; i < g.size(); i++) {
            var entries = dispatcher(g.at(i)); if (entries == null) continue;
            Constants state = constants.before(i); int[] args = ConstantEvaluator.arguments(g.at(i));
            if (state == null || !(state.get(args[0]) instanceof Integer id)) continue;
            var entry = entries.get(id); if (entry == null || entry.target().member() == null) continue;
            Plan plan = plan(context, g, i, entry, args, constants, types, live, predecessors);
            if (plan != null) plans.add(plan);
        }
        if (plans.isEmpty()) return 0;
        List<Slot> slots = new ArrayList<>(); Map<Integer, List<BuilderInstruction>> prefixes = new TreeMap<>();
        Map<Integer, List<BuilderInstruction>> replacements = new TreeMap<>(); Set<Integer> remove = new TreeSet<>(); int scratch = 0, count = 0;
        plans.sort(Comparator.comparingInt(Plan::start).thenComparingInt(Plan::at));
        for (Plan plan : plans) {
            int offset = 0;
            for (boolean retry = true; retry;) { retry = false; for (Slot slot : slots) {
                if (plan.start() <= slot.end() && plan.at() >= slot.start() && offset < slot.base() + slot.count() && offset + plan.words() > slot.base()) { offset = slot.base() + slot.count(); retry = true; }
            } }
            int bank = g.registers() + offset;
            if (bank + plan.words() > 65500 || plan.words() > 255) continue;
            List<BuilderInstruction> call = new ArrayList<>();
            if (plan.receiver() >= 0) call.add(ProxyInstructions.move(bank, plan.receiver(), plan.target().getDefiningClass()));
            call.add(new BuilderInstruction3rc(plan.opcode(), plan.words() == 0 ? 0 : bank, plan.words(), plan.target()));
            Map<Integer, List<BuilderInstruction>> resultEdits = new HashMap<>(); Set<Integer> resultRemove = new HashSet<>();
            if (!result(g, plan.at(), plan.target().getReturnType(), live, predecessors, resultEdits, resultRemove)) continue;
            if (remove.contains(plan.at()) || replacements.containsKey(plan.at())) continue;
            for (Capture capture : plan.captures()) prefixes.computeIfAbsent(capture.at(), k -> new ArrayList<>()).add(ProxyInstructions.move(bank + capture.word(), capture.source(), capture.type()));
            replacements.put(plan.at(), call); replacements.putAll(resultEdits); remove.addAll(plan.remove()); remove.addAll(resultRemove);
            slots.add(new Slot(plan.start(), plan.at(), offset, plan.words())); scratch = Math.max(scratch, offset + plan.words()); count++;
        }
        List<Edits.Edit> edits = new ArrayList<>(); List<BuilderInstruction> deleted = new ArrayList<>();
        Set<Integer> affected = new TreeSet<>(prefixes.keySet()); affected.addAll(replacements.keySet()); affected.addAll(remove);
        for (int at : affected) {
            List<BuilderInstruction> code = new ArrayList<>(prefixes.getOrDefault(at, List.of()));
            if (replacements.containsKey(at)) code.addAll(replacements.get(at));
            else if (!remove.contains(at)) code.add(Edits.copy(g.at(at), g.registers()));
            if (code.isEmpty()) { var nop = new BuilderInstruction10x(Opcode.NOP); code.add(nop); deleted.add(nop); }
            edits.add(new Edits.Edit(at, false, code));
        }
        Edits.apply(context.code(), edits); BitSet deletedIndices = new BitSet();
        for (var i : deleted) deletedIndices.set(i.getLocation().getIndex()); ExceptionEdits.remove(context, deletedIndices);
        if (scratch > 0) context.appendScratchRegisters(scratch);
        return count;
    }
    private Map<Integer, ReflectionModel.Entry> dispatcher(Instruction i) {
        return (i.getOpcode() == Opcode.INVOKE_STATIC || i.getOpcode() == Opcode.INVOKE_STATIC_RANGE)
                ? model.dispatchers.get(Signatures.of(ReflectionModel.methodRef(i))) : null;
    }
    private Plan plan(MethodContext context, CodeGraph g, int at, ReflectionModel.Entry entry, int[] args,
                      ConstantAnalysis constants, ReflectionTypes types, RegisterLiveness live, int[] predecessors) {
        Reference member = entry.target().member(); var resolved = resolver.resolve(member); if (resolved == null) return null;
        boolean isStatic = AccessFlags.STATIC.isSet(resolved.flags());
        String caller = context.original().getDefiningClass(), owner = member instanceof MethodReference m ? m.getDefiningClass() : ((FieldReference)member).getDefiningClass();
        if (!isStatic && (args.length < 2 || !assignable(types.get(at, args[1]), owner))) return null;
        List<String> params = member instanceof MethodReference m ? m.getParameterTypes().stream().map(Object::toString).toList() : List.of();
        if (member instanceof MethodReference m && (m.getName().startsWith("<") || ((AccessFlags.PRIVATE.isSet(resolved.flags()) || AccessFlags.INTERFACE.isSet(resolved.ownerFlags())) && !owner.equals(resolved.owner())))) return null;
        List<Capture> captures = new ArrayList<>(); Set<Integer> remove = new HashSet<>(); int start = at, words = isStatic ? 0 : 1;
        if (member instanceof MethodReference) {
            if (args.length != 3) return null;
            int array = args[2], allocation = -1, alias = -1;
            if (!isStatic && args[1] == array) return null;
            if (!(params.isEmpty() && types.get(at, array) != null && types.get(at, array).type().equals("null"))) {
                // High-register DEX often stages the array into a low register immediately before invoke.
                if (at > 0 && g.at(at - 1).getOpcode().name.startsWith("move-object") && g.at(at - 1) instanceof TwoRegisterInstruction move
                        && move.getRegisterA() == array) {
                    if (live.liveAfter(at, array) || predecessors[at] != 1) return null;
                    alias = at - 1; array = move.getRegisterB(); remove.add(alias);
                    if (!isStatic && args[1] == array) return null;
                }
                for (int i = alias < 0 ? at - 1 : alias - 1; i >= 0; i--) {
                    if (g.successors(i).size() != 1 || g.successors(i).get(0) != i + 1 || predecessors[i + 1] != 1) return null;
                    if (RegisterLiveness.writes(g.at(i)).get(array)) { allocation = i; break; }
                }
                if (allocation > 0 && g.at(allocation).getOpcode().name.startsWith("move-object") && g.at(allocation) instanceof TwoRegisterInstruction transfer
                        && transfer.getRegisterA() == array && g.at(allocation - 1).getOpcode() == Opcode.NEW_ARRAY
                        && ((OneRegisterInstruction)g.at(allocation - 1)).getRegisterA() == transfer.getRegisterB()
                        && !live.liveAfter(allocation, transfer.getRegisterB()) && predecessors[allocation] == 1
                        && g.successors(allocation - 1).equals(List.of(allocation))) {
                    remove.add(allocation); allocation--;
                }
                if (allocation < 0 || g.at(allocation).getOpcode() != Opcode.NEW_ARRAY || live.liveAfter(at, array)) return null;
                var instruction = (TwoRegisterInstruction)g.at(allocation);
                if (!((TypeReference)((ReferenceInstruction)instruction).getReference()).getType().equals("[Ljava/lang/Object;")) return null;
                Constants state = constants.before(allocation);
                if (state == null || !Objects.equals(state.get(instruction.getRegisterB()), params.size())) return null;
                // A private array must not escape through any exceptional successor either.
                for (int i = allocation + 1; i <= at; i++) for (int handler : g.handlers(i)) if (live.liveBefore(handler, array)) return null;
                int[] stores = new int[params.size()]; Arrays.fill(stores, -1);
                for (int i = allocation + 1; i < at; i++) if (i != alias && RegisterLiveness.reads(g.at(i)).get(array)) {
                    if (g.at(i).getOpcode() != Opcode.APUT_OBJECT) return null;
                    var store = (ThreeRegisterInstruction)g.at(i);
                    if (store.getRegisterB() != array || store.getRegisterA() == array || store.getRegisterC() == array) return null;
                    Constants before = constants.before(i);
                    if (before == null || !(before.get(store.getRegisterC()) instanceof Integer index) || index < 0 || index >= stores.length) return null;
                    stores[index] = i; remove.add(i);
                }
                for (int n = 0; n < params.size(); n++) {
                    if (stores[n] < 0) return null;
                    int store = stores[n], source = ((ThreeRegisterInstruction)g.at(store)).getRegisterA(); String type = params.get(n);
                    ReflectionTypes.Fact fact = types.get(store, source);
                    if (ReflectionCode.reference(type)) {
                        if (!assignable(fact, type)) return null;
                        captures.add(new Capture(store, source, type, words));
                    } else {
                        if (fact == null || !fact.type().equals(ReflectionCode.box(type)) || fact.boxing() <= allocation || fact.boxing() >= store) return null;
                        MethodReference box = ReflectionModel.methodRef(g.at(fact.boxing()));
                        if (!box.getParameterTypes().equals(List.of(type))) return null;
                        captures.add(new Capture(fact.boxing(), ConstantEvaluator.arguments(g.at(fact.boxing()))[0], type, words));
                    }
                    words += ProxyInstructions.wide(type) ? 2 : 1;
                }
                remove.add(allocation); start = allocation;
            }
        }
        MethodReference target; Opcode op;
        if (member instanceof MethodReference method && ProxyAccess.member(context.dex(), resolver, member, caller, false)) {
            target = method; op = isStatic ? Opcode.INVOKE_STATIC_RANGE : AccessFlags.PRIVATE.isSet(resolved.flags()) ? Opcode.INVOKE_DIRECT_RANGE
                    : AccessFlags.INTERFACE.isSet(resolved.ownerFlags()) ? Opcode.INVOKE_INTERFACE_RANGE : Opcode.INVOKE_VIRTUAL_RANGE;
        } else {
            target = accessors.get(member, resolved, caller); if (target == null) return null; op = Opcode.INVOKE_STATIC_RANGE;
        }
        return new Plan(at, start, target, op, isStatic ? -1 : args[1], captures, words, remove);
    }
    private boolean assignable(ReflectionTypes.Fact fact, String expected) { return fact != null && resolver.assignable(fact.type(), expected); }
    private boolean result(CodeGraph g, int at, String type, RegisterLiveness live, int[] pred,
                           Map<Integer, List<BuilderInstruction>> edits, Set<Integer> remove) {
        if (at + 1 >= g.size() || g.at(at + 1).getOpcode() != Opcode.MOVE_RESULT_OBJECT) return true;
        if (pred[at + 1] != 1) return false;
        int reg = ((OneRegisterInstruction)g.at(at + 1)).getRegisterA();
        if (type.equals("V")) { edits.put(at + 1, List.of(Edits.constant(reg, 0))); return true; }
        if (ReflectionCode.reference(type)) {
            if (at + 2 < g.size() && pred[at + 2] == 1 && g.at(at + 2).getOpcode() == Opcode.CHECK_CAST
                    && ((OneRegisterInstruction)g.at(at + 2)).getRegisterA() == reg
                    && resolver.assignable(type, ((TypeReference)((ReferenceInstruction)g.at(at + 2)).getReference()).getType())) remove.add(at + 2);
            return true;
        }
        if (at + 3 >= g.size() || g.at(at + 2).getOpcode() != Opcode.CHECK_CAST
                || ((OneRegisterInstruction)g.at(at + 2)).getRegisterA() != reg
                || !((TypeReference)((ReferenceInstruction)g.at(at + 2)).getReference()).getType().equals(ReflectionCode.box(type))) return false;
        Opcode invoke = g.at(at + 3).getOpcode();
        if (invoke != Opcode.INVOKE_VIRTUAL && invoke != Opcode.INVOKE_VIRTUAL_RANGE) return false;
        MethodReference unbox = ReflectionModel.methodRef(g.at(at + 3));
        if (!Signatures.of(unbox).equals(ReflectionCode.box(type) + "->" + ReflectionCode.unbox(type) + "()" + type)
                || !Arrays.equals(ConstantEvaluator.arguments(g.at(at + 3)), new int[]{reg})) return false;
        Opcode move = ProxyInstructions.wide(type) ? Opcode.MOVE_RESULT_WIDE : Opcode.MOVE_RESULT;
        if (at + 4 >= g.size() || g.at(at + 4).getOpcode() != move) {
            if (live.liveAfter(at + 3, reg)) return false;
            for (int n = at + 1; n <= at + 3; n++) if (pred[n] != 1 || !g.protection(at).equals(g.protection(n))) return false;
            remove.add(at + 1); remove.add(at + 2); remove.add(at + 3); return true;
        }
        int dest = ((OneRegisterInstruction)g.at(at + 4)).getRegisterA();
        if (dest != reg && live.liveAfter(at + 4, reg)) return false;
        for (int n = at + 1; n <= at + 4; n++) if (pred[n] != 1 || !g.protection(at).equals(g.protection(n))) return false;
        edits.put(at + 1, List.of(new BuilderInstruction11x(move, dest)));
        remove.add(at + 2); remove.add(at + 3); remove.add(at + 4); return true;
    }

    static int fields(MethodContext context, MemberResolver resolver, Map<String, FieldReference> readers) {
        if (readers.isEmpty()) return 0;
        CodeGraph g = context.graph(); RegisterLiveness live = new RegisterLiveness(g);
        List<Edits.Edit> edits = new ArrayList<>(); List<BuilderInstruction> deleted = new ArrayList<>(); int count = 0;
        for (int i = 0; i + 1 < g.size(); i++) {
            Instruction call = g.at(i);
            if (call.getOpcode() != Opcode.INVOKE_STATIC && call.getOpcode() != Opcode.INVOKE_STATIC_RANGE) continue;
            FieldReference field = readers.get(Signatures.of(ReflectionModel.methodRef(call)));
            if (field == null || !ProxyAccess.member(context.dex(), resolver, field, context.original().getDefiningClass(), false)) continue;
            var member = resolver.resolve(field); if (member == null) continue;
            String type = field.getType(); boolean wide = ProxyInstructions.wide(type), ref = ReflectionCode.reference(type);
            Opcode result = ref ? Opcode.MOVE_RESULT_OBJECT : wide ? Opcode.MOVE_RESULT_WIDE : Opcode.MOVE_RESULT;
            if (g.at(i + 1).getOpcode() != result || g.leaders().contains(i + 1)) continue;
            int dest = ((OneRegisterInstruction)g.at(i + 1)).getRegisterA();
            int[] args = ConstantEvaluator.arguments(call); boolean isStatic = AccessFlags.STATIC.isSet(member.flags());
            if (args.length != (isStatic ? 0 : 1)) continue;
            String suffix = ref ? "_OBJECT" : wide ? "_WIDE" : switch(type) { case "Z" -> "_BOOLEAN"; case "B" -> "_BYTE"; case "C" -> "_CHAR"; case "S" -> "_SHORT"; default -> ""; };
            List<BuilderInstruction> code = new ArrayList<>();
            if (isStatic) code.add(new BuilderInstruction21c(Opcode.valueOf("SGET" + suffix), dest, field));
            else if (dest < 16 && args[0] < 16) code.add(new BuilderInstruction22c(Opcode.valueOf("IGET" + suffix), dest, args[0], field));
            else {
                int scratch = -1;
                for (int r = 0; r < Math.min(16, g.registers() - (wide ? 1 : 0)); r++)
                    if (!live.liveAfter(i, r) && (!wide || !live.liveAfter(i, r + 1))) { scratch = r; break; }
                if (scratch < 0) continue;
                code.add(ProxyInstructions.move(scratch, args[0], field.getDefiningClass()));
                code.add(new BuilderInstruction22c(Opcode.valueOf("IGET" + suffix), scratch, scratch, field));
                code.add(ProxyInstructions.move(dest, scratch, type));
            }
            edits.add(new Edits.Edit(i, false, code));
            var nop = new BuilderInstruction10x(Opcode.NOP); deleted.add(nop);
            edits.add(new Edits.Edit(i + 1, false, List.of(nop))); count++;
        }
        Edits.apply(context.code(), edits); BitSet remove = new BitSet();
        for (var nop : deleted) remove.set(nop.getLocation().getIndex()); ExceptionEdits.remove(context, remove);
        return count;
    }
}
