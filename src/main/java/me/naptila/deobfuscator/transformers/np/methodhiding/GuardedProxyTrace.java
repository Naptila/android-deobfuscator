package me.naptila.deobfuscator.transformers.np.methodhiding;

import java.util.*;

import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.transformers.np.analysis.NpHelpers;
import me.naptila.deobfuscator.transformers.np.analysis.NpModel;
import me.naptila.deobfuscator.transformers.np.support.ProxyAccess;
import me.naptila.deobfuscator.transformers.np.support.ProxyInstructions;

import org.jf.dexlib2.AccessFlags;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.Reference;
import org.jf.dexlib2.immutable.ImmutableMethodImplementation;

final class GuardedProxyTrace {
   static HiddenProxies.Template recognize(DexContext dex, NpModel model, Method method) {
      return recognize(dex, model, method, Map.of());
   }

   static HiddenProxies.Template recognize(DexContext dex, NpModel model, Method method, Map<String, Integer> integerGuards) {
      return recognize(dex, model, method, integerGuards, false, false);
   }

   static HiddenProxies.Template recognize(DexContext dex, NpModel model, Method method, Map<String, Integer> integerGuards, boolean proxyClass) {
      return recognize(dex, model, method, integerGuards, false, proxyClass);
   }

   /** The original call remains, so its trace may contain several ordered effects. */
   static HiddenProxies.Template valueTrace(DexContext dex, NpModel model, Method method, Map<String, Integer> integerGuards) {
      return recognize(dex, model, method, integerGuards, true, false);
   }

   private static HiddenProxies.Template recognize(DexContext dex, NpModel model, Method method,
         Map<String, Integer> integerGuards, boolean valueOnly, boolean proxyClass) {
      int flags = method.getAccessFlags();
      if (method.getImplementation() != null
         && !method.getName().startsWith("<")
         && AccessFlags.PUBLIC.isSet(flags)
         && AccessFlags.STATIC.isSet(flags)
         && !AccessFlags.SYNCHRONIZED.isSet(flags)
         && !AccessFlags.DECLARED_SYNCHRONIZED.isSet(flags)
         && method.getImplementation().getTryBlocks().isEmpty()) {
         CodeGraph graph = new CodeGraph(method.getImplementation());
         boolean relevant = proxyClass || model.relevant(graph);
         if (!relevant && !integerGuards.isEmpty()) {
            for (int i = 0; i < graph.size(); i++) if (graph.at(i) instanceof ReferenceInstruction ref
                  && ref.getReference() instanceof MethodReference call && integerGuards.containsKey(Signatures.of(call))) relevant = true;
         }
         if (graph.size() >= (proxyClass ? 2 : 5) && graph.size() <= 512 && relevant) {
            MethodReference guard = null;
            Constants state = new Constants();
            List<Instruction> trace = new ArrayList<>();
            boolean branch = false;
            int cursor = 0;

            for (int budget = 0; budget < 4096; budget++) {
               if (cursor < 0 || cursor >= graph.size() || graph.isPayload(cursor)) {
                  return null;
               }

               Instruction insn = graph.at(cursor);
               Opcode op = insn.getOpcode();
               if (op.name.startsWith("return")) {
                  if (branch && guard != null || proxyClass) {
                     trace.add(insn);
                     return validate(method, trace, graph.registers(), guard, model, integerGuards, valueOnly, proxyClass);
                  }

                  return null;
               }

               if (!CodeGraph.isIf(op) && !CodeGraph.isSwitch(op) && !CodeGraph.isGoto(op)) {
                  if (op == Opcode.MOVE_EXCEPTION || op == Opcode.CONST_METHOD_HANDLE || op == Opcode.CONST_METHOD_TYPE || op == Opcode.FILL_ARRAY_DATA) {
                     return null;
                  }

                  if ((op == Opcode.INVOKE_STATIC || op == Opcode.INVOKE_STATIC_RANGE)
                     && insn instanceof ReferenceInstruction ref
                     && ref.getReference() instanceof MethodReference call) {
                     String sig = Signatures.of(call);
                     int[] args = ConstantEvaluator.arguments(insn);
                     NpHelpers.Guard summary = model.helpers().guards().get(sig);
                     boolean knownGuard = summary != null
                        && args.length == 0
                        && model.fields().containsKey(summary.field())
                        && dex.fields().containsKey(summary.field())
                        && ProxyAccess.member(dex, (Reference)dex.fields().get(summary.field()), call.getDefiningClass(), false);
                     boolean hash = model.helpers().hashes().contains(sig) && args.length == 1 && state.get(args[0]) instanceof String;
                     Integer alias = args.length == 0 ? integerGuards.get(sig) : null;
                     if ((knownGuard || hash || alias != null) && ProxyAccess.member(dex, call, method.getDefiningClass(), false)) {
                        model.step(insn, state);
                        if (alias != null) state.result(alias);
                        if (knownGuard || alias != null) {
                           guard = call;
                        }

                        if (alias != null || knownGuard && !model.helpers().removableGuards().contains(sig) || hash && !model.helpers().removableHashes().contains(sig)) {
                           trace.add(insn);
                        }

                        if (cursor + 1 < graph.size() && graph.at(cursor + 1).getOpcode() == Opcode.MOVE_RESULT) {
                           int reg = NpHelpers.reg(graph.at(cursor + 1));
                           if (!(state.result() instanceof Integer value)) {
                              return null;
                           }

                           trace.add(Edits.constant(reg, value));
                           model.step(graph.at(++cursor), state);
                        }

                        cursor++;
                        continue;
                     }
                  }

                  if (op == Opcode.SGET
                     && insn instanceof ReferenceInstruction ref
                     && ref.getReference() instanceof FieldReference f
                     && model.fields().containsKey(Signatures.of(f))
                     && ProxyAccess.member(dex, f, method.getDefiningClass(), false)) {
                     if (!ProxyAccess.initializationSafe(dex, f.getDefiningClass(), method.getDefiningClass())) {
                        trace.add(insn);
                     }

                     model.step(insn, state);
                     trace.add(Edits.constant(NpHelpers.reg(insn), model.fields().get(Signatures.of(f))));
                     cursor++;
                  } else {
                     model.step(insn, state);
                     if ((DeadAssignments.isPure(insn) && op.name.contains("-int")
                           || op.name.startsWith("div-int") || op.name.startsWith("rem-int"))
                           && state.get(NpHelpers.reg(insn)) instanceof Integer value) {
                        trace.add(Edits.constant(NpHelpers.reg(insn), value));
                     } else {
                        trace.add(insn);
                     }

                     if (graph.successors(cursor).size() != 1) {
                        return null;
                     }

                     cursor = graph.successors(cursor).get(0);
                  }
               } else {
                  List<Integer> next = ConstantBranches.successors(graph, cursor, state);
                  if (next.size() != 1) {
                     return null;
                  }

                  if (CodeGraph.isIf(op)) {
                     if (ConstantBranches.decision(insn, state) == null) {
                        return null;
                     }

                     branch = true;
                  }

                  if (CodeGraph.isSwitch(op) && !(state.get(NpHelpers.reg(insn)) instanceof Integer)) {
                     return null;
                  }

                  if (CodeGraph.isSwitch(op)) {
                     branch = true;
                  }

                  cursor = next.get(0);
               }
            }

            return null;
         } else {
            return null;
         }
      } else {
         return null;
      }
   }

   private static HiddenProxies.Template validate(Method method, List<Instruction> trace, int registers, MethodReference guard, NpModel model,
         Map<String, Integer> integerGuards, boolean valueOnly, boolean proxyClass) {
      boolean changed;
      do {
         changed = false;
         CodeGraph graph = new CodeGraph(new ImmutableMethodImplementation(registers, trace, List.of(), List.of()));
         RegisterLiveness live = new RegisterLiveness(graph);
         List<Instruction> retained = new ArrayList<>();

         for (int i = 0; i < trace.size(); i++) {
            Instruction insn = trace.get(i);
            if (insn.getOpcode() != Opcode.NOP && (!DeadAssignments.isPure(insn) || !live.deadAfter(i, insn))) {
               retained.add(insn);
            } else {
               changed = true;
            }
         }

         trace = retained;
      } while (changed);

      trace = GuardedProxyTrace.simplifyCopies(trace, registers);
      if (!trace.isEmpty() && trace.size() <= 128 && (trace.size() != 1 || trace.get(0).getOpcode() != Opcode.RETURN_VOID)) {
         int actions = 0;

         for (Instruction insn : trace.subList(0, trace.size() - 1)) {
            String name = insn.getOpcode().name;
            if (name.startsWith("invoke-static")
               || name.startsWith("invoke-virtual")
               || name.startsWith("invoke-interface")
               || name.startsWith("invoke-direct")) {
               if (((MethodReference)((ReferenceInstruction)insn).getReference()).getName().startsWith("<")) {
                  return null;
               }

               String sig = Signatures.of((MethodReference)((ReferenceInstruction)insn).getReference());
               if (!model.helpers().guards().containsKey(sig) && !integerGuards.containsKey(sig)) {
                  actions++;
               }
            } else if (name.startsWith("iget") || name.startsWith("sget") || name.startsWith("iput") || name.startsWith("sput")) {
               actions++;
            } else if (!name.startsWith("const") && !name.startsWith("move") && insn.getOpcode() != Opcode.CHECK_CAST) {
               return null;
            }
         }

         if (!valueOnly && !proxyClass && actions > 1) {
            return null;
         }

         CodeGraph graph = new CodeGraph(new ImmutableMethodImplementation(registers, trace, List.of(), List.of()));
         RegisterLiveness live = new RegisterLiveness(graph);
         int words = method.getParameterTypes().stream().mapToInt(t -> ProxyInstructions.wide(t.toString()) ? 2 : 1).sum();

         for (int r = 0; r < registers - words; r++) {
            if (live.liveBefore(0, r)) {
               return null;
            }
         }

         BitSet used = new BitSet();
         used.set(registers - words, registers);

         for (Instruction insn : trace) {
            used.or(RegisterLiveness.reads(insn));
            used.or(RegisterLiveness.writes(insn));
         }

         int[] mapping = new int[registers];
         Arrays.fill(mapping, -1);
         int count = 0;

         for (int r = used.nextSetBit(0); r >= 0; r = used.nextSetBit(r + 1)) {
            mapping[r] = count++;
         }

         List<Instruction> compact = new ArrayList<>();

         for (Instruction insn : trace) {
            Instruction copy = ProxyInstructions.copy(insn, r -> mapping[r]);
            if (copy == null) {
               return null;
            }

            compact.add(copy);
         }

         return new HiddenProxies.Template(method, List.copyOf(compact.subList(0, compact.size() - 1)), compact.get(compact.size() - 1), guard, true, count, proxyClass);
      } else {
         return null;
      }
   }

    static List<Instruction> simplifyCopies(List<Instruction> input, int registers) {
        List<Instruction> code = new ArrayList<>(input);
        while (true) {
            CodeGraph graph = new CodeGraph(new ImmutableMethodImplementation(registers, code, List.of(), List.of()));
            RegisterLiveness live = new RegisterLiveness(graph); boolean changed = false;
            for (int at = 0; at < code.size(); at++) {
                Instruction insn = code.get(at);
                if (!(insn instanceof TwoRegisterInstruction move) || !insn.getOpcode().name.startsWith("move")) continue;
                int width = insn.getOpcode().name.startsWith("move-wide") ? 2 : 1;
                int dest = move.getRegisterA(), source = move.getRegisterB();
                if (dest == source) { code.remove(at); changed = true; break; }
                if (width == 2 && Math.abs(dest - source) == 1) continue;
                BitSet aliases = new BitSet(); aliases.set(dest, dest + width);
                BitSet sources = new BitSet(); sources.set(source, source + width);
                Map<Integer, Instruction> replacements = new HashMap<>(); boolean safe = true;
                for (int next = at + 1; next < code.size(); next++) {
                    Instruction use = code.get(next);
                    BitSet reads = RegisterLiveness.reads(use), writes = RegisterLiveness.writes(use);
                    boolean cast = use.getOpcode() == Opcode.CHECK_CAST && reads.intersects(aliases);
                    boolean aliasLive = false;
                    for (int r = dest; r < dest + width; r++) aliasLive |= live.liveAfter(next, r);
                    if (writes.intersects(aliases) && !cast) {
                        BitSet killed = (BitSet)writes.clone(); killed.and(aliases);
                        if (reads.intersects(aliases) || killed.cardinality() != width && aliasLive) safe = false;
                        break;
                    }
                    if (writes.intersects(sources) && aliasLive) { safe = false; break; }
                    if (reads.intersects(aliases)) {
                        Instruction replacement = ProxyInstructions.copy(use, r -> r >= dest && r < dest + width ? source + r - dest : r);
                        if (replacement == null) { safe = false; break; }
                        replacements.put(next, replacement);
                    }
                    if (!aliasLive) break;
                }
                if (!safe) continue;
                replacements.forEach(code::set); code.remove(at); changed = true; break;
            }
            if (!changed) return List.copyOf(code);
        }
    }
}
