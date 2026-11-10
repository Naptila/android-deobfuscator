package me.naptila.deobfuscator.transformers.np.controlflow;

import me.naptila.deobfuscator.transformers.np.analysis.NpHelpers;
import me.naptila.deobfuscator.transformers.np.analysis.NpModel;

import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.RegisterLiveness;
import me.naptila.deobfuscator.dex.Signatures;
import java.util.HashSet;
import java.util.Set;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.reference.MethodReference;

/** Shared recognition of hash/switch dispatcher shapes for control-flow recovery and cleanup eligibility. */
public final class FlowerPatterns {
   private FlowerPatterns() {
   }

   public static Set<Integer> find(CodeGraph graph, NpModel model) {
      Set<Integer> result = new HashSet<>();

      for (int i = 0; i < graph.size(); i++) {
         if (CodeGraph.isSwitch(graph.at(i).getOpcode())) {
            int register = NpHelpers.reg(graph.at(i));

            for (int n = i - 1; n >= Math.max(1, i - 16) && !graph.leaders().contains(n + 1); n--) {
               Instruction instruction = graph.at(n);
               if (instruction.getOpcode() == Opcode.MOVE_RESULT && NpHelpers.reg(instruction) == register) {
                  Instruction invoke = graph.at(n - 1);
                  if ((invoke.getOpcode() == Opcode.INVOKE_STATIC || invoke.getOpcode() == Opcode.INVOKE_STATIC_RANGE)
                     && invoke instanceof ReferenceInstruction r
                     && r.getReference() instanceof MethodReference method
                     && model.helpers().hashes().contains(Signatures.of(method))) {
                     result.add(i);
                  }
                  break;
               }

               Opcode op = instruction.getOpcode();
               if (op != Opcode.NOP
                     && op != Opcode.CONST
                     && op != Opcode.CONST_4
                     && op != Opcode.CONST_16
                     && op != Opcode.CONST_HIGH16
                     && op != Opcode.MOVE
                     && op != Opcode.MOVE_FROM16
                     && op != Opcode.MOVE_16
                  || RegisterLiveness.writes(instruction).get(register)) {
                  break;
               }
            }

            if (i + 1 < graph.size() && CodeGraph.isGoto(graph.at(i + 1).getOpcode())) {
               int start = graph.successors(i + 1).get(0);
               if (start >= 0 && start < i && i - start <= 3) {
                  int xor = 0;
                  boolean valid = true;

                  for (int n = start; n < i; n++) {
                     Opcode op = graph.at(n).getOpcode();
                     if (op != Opcode.XOR_INT && op != Opcode.XOR_INT_2ADDR && op != Opcode.XOR_INT_LIT8 && op != Opcode.XOR_INT_LIT16) {
                        valid &= op == Opcode.CONST || op == Opcode.CONST_4 || op == Opcode.CONST_16 || op == Opcode.CONST_HIGH16 || op == Opcode.NOP;
                     } else {
                        xor++;
                        valid &= NpHelpers.reg(graph.at(n)) == register;
                     }
                  }

                  if (valid && xor == 1) {
                     result.add(i);
                  }
               }
            }
         }
      }

      return result;
   }
}
