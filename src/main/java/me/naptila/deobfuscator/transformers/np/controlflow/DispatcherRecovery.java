package me.naptila.deobfuscator.transformers.np.controlflow;

import me.naptila.deobfuscator.transformers.np.analysis.NpHelpers;
import me.naptila.deobfuscator.transformers.np.analysis.NpModel;

import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.ConstantAnalysis;
import me.naptila.deobfuscator.dex.ConstantBranches;
import me.naptila.deobfuscator.dex.ConstantEvaluator;
import me.naptila.deobfuscator.dex.Constants;
import me.naptila.deobfuscator.dex.Edits;
import me.naptila.deobfuscator.dex.MethodContext;
import me.naptila.deobfuscator.dex.Signatures;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.BuilderInstruction;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.reference.MethodReference;

final class DispatcherRecovery {
   private final NpModel model;
   private final boolean allowDefault;
   private final boolean integerPrefix;

   DispatcherRecovery(NpModel model, boolean allowDefault, boolean integerPrefix) {
      this.model = model;
      this.allowDefault = allowDefault;
      this.integerPrefix = integerPrefix;
   }

   PassResult run(MethodContext context, Set<Integer> dispatchers) {
      return this.run(context, dispatchers, Set.of());
   }

   PassResult run(MethodContext context, Set<Integer> dispatchers, Set<Integer> comparisons) {
      CodeGraph graph = context.graph();
      ConstantAnalysis facts = this.model.analyze(graph);
      List<Edits.Edit> edits = new ArrayList<>();
      int unresolved = 0;
      Set<String> notes = new LinkedHashSet<>();

      for (int source = 0; source < graph.size(); source++) {
         Instruction insn = graph.at(source);
         if (!graph.isPayload(source)) {
            boolean jump = CodeGraph.isGoto(insn.getOpcode());
            int target = jump ? graph.successors(source).get(0) : (insn.getOpcode().canContinue() ? source + 1 : -1);
            if (target >= 0 && target < graph.size() && (jump || graph.leaders().contains(target))) {
               Constants state = facts.before(source);
               if (state != null) {
                  this.model.step(insn, state);
                  List<BuilderInstruction> route = this.specialize(context, graph, source, target, dispatchers, comparisons, state, notes);
                  if (route == null) {
                     if (dispatchers.contains(target)) {
                        unresolved++;
                     }
                  } else {
                     edits.add(new Edits.Edit(jump ? source : target, !jump, route));
                  }
               }
            }
         }
      }

      Edits.apply(context.code(), edits);
      if (unresolved != 0) {
         notes.add("unresolved NP dispatcher edges: " + unresolved);
      }

      return new PassResult(edits.size(), List.copyOf(notes));
   }

   private List<BuilderInstruction> specialize(
      MethodContext context, CodeGraph graph, int source, int start, Set<Integer> dispatchers, Set<Integer> comparisons, Constants state, Set<String> notes
   ) {
      List<BuilderInstruction> prefix = new ArrayList<>();
      Set<Integer> visited = new HashSet<>();
      int pc = start;

      for (int budget = 0; budget < ComparisonDispatchers.PATH_LIMIT && pc < graph.size() && visited.add(pc); budget++) {
         Instruction i = graph.at(pc);
         Opcode op = i.getOpcode();
         if (comparisons.contains(pc)) {
            Boolean take = ConstantBranches.decision(i, state);
            if (take == null) {
               return null;
            }

            if (take) {
               int destination = graph.successors(pc).get(0);
               if (visited.contains(destination)) {
                  return null;
               }

               prefix.add(Edits.jump(context.code(), destination));
               return prefix;
            }

            pc++;
         } else {
            if (dispatchers.contains(pc)) {
               if (!(state.get(NpHelpers.reg(i)) instanceof Integer key)) {
                  return null;
               }

               int destination = graph.switchTarget(pc, key);
               if (destination != pc && (this.allowDefault || destination != pc + 1) && !visited.contains(destination)) {
                  prefix.add(Edits.jump(context.code(), destination));
                  return prefix;
               }

               return null;
            }

            if (CodeGraph.isGoto(op)) {
               pc = graph.successors(pc).get(0);
            } else if (op == Opcode.NOP) {
               pc++;
            } else {
               boolean allowed = op.name.startsWith("const") && !op.name.equals("const-class")
                  || op == Opcode.MOVE
                  || op == Opcode.MOVE_FROM16
                  || op == Opcode.MOVE_16
                  || op == Opcode.MOVE_OBJECT
                  || op == Opcode.MOVE_OBJECT_FROM16
                  || op == Opcode.MOVE_OBJECT_16
                  || op == Opcode.MOVE_WIDE
                  || op == Opcode.MOVE_WIDE_FROM16
                  || op == Opcode.MOVE_WIDE_16
                  || op == Opcode.MOVE_RESULT;
               if (op == Opcode.MOVE_RESULT && (prefix.isEmpty() || !prefix.get(prefix.size() - 1).getOpcode().name.startsWith("invoke-"))) {
                  return null;
               }

               if (op == Opcode.SGET && i instanceof ReferenceInstruction r && r.getReference() instanceof FieldReference f) {
                  allowed = this.model.fields().containsKey(Signatures.of(f));
               }

               if ((op == Opcode.INVOKE_STATIC || op == Opcode.INVOKE_STATIC_RANGE)
                  && i instanceof ReferenceInstruction r
                  && r.getReference() instanceof MethodReference m) {
                  allowed = this.model.helpers().hashes().contains(Signatures.of(m)) || this.model.helpers().guards().containsKey(Signatures.of(m));
               }

               if (this.integerPrefix && (op == Opcode.XOR_INT || op == Opcode.XOR_INT_2ADDR || op == Opcode.XOR_INT_LIT8 || op == Opcode.XOR_INT_LIT16)) {
                  allowed = true;
               }

               // Shared arithmetic tails lose operand correlations at the global join.
               // Evaluate each incoming edge separately, including overflowing int math.
               // Unknown operands and division by zero must keep the original route.
               Integer integerValue = constantIntegerArithmetic(i, state);
               if (integerValue != null) {
                  allowed = true;
               }

               if (!allowed) {
                  return null;
               }

               if (op.canThrow() && !graph.protection(pc).equals(graph.protection(source))) {
                  notes.add("NP route retained: throwing instruction would change exception handlers");
                  return null;
               }

               this.model.step(i, state);
               if (integerValue != null) {
                  prefix.add(Edits.constant(NpHelpers.reg(i), integerValue));
               } else if (this.integerPrefix && op.name.startsWith("xor-int") && state.get(NpHelpers.reg(i)) instanceof Integer value) {
                  prefix.add(Edits.constant(NpHelpers.reg(i), value));
               } else {
                  prefix.add(Edits.copy(i, graph.registers()));
               }

               pc++;
            }
         }
      }

      return null;
   }

   private static Integer constantIntegerArithmetic(Instruction instruction, Constants state) {
      if (!instruction.getOpcode().name.contains("-int")) {
         return null;
      }
      Constants trial = state.copy();
      return ConstantEvaluator.step(instruction, trial) && trial.get(NpHelpers.reg(instruction)) instanceof Integer value ? value : null;
   }
}
