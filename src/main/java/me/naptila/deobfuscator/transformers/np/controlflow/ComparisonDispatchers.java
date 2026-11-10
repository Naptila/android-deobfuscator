package me.naptila.deobfuscator.transformers.np.controlflow;

import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.RegisterLiveness;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.OneRegisterInstruction;
import org.jf.dexlib2.iface.instruction.ThreeRegisterInstruction;
import org.jf.dexlib2.iface.instruction.TwoRegisterInstruction;

/** Recognizes bounded XOR comparison dispatchers, including rotated chains and state-copy backedges. */
public final class ComparisonDispatchers {
   static final int PATH_LIMIT = 128;
   private ComparisonDispatchers() {
   }

   public static Set<Integer> find(CodeGraph graph) {
      Set<Integer> result = new HashSet<>();

      for (int start = 0; start < graph.size(); start++) {
         if (isXor(graph.at(start).getOpcode())) {
            int selector = ((OneRegisterInstruction)graph.at(start)).getRegisterA();
            BitSet aliases = new BitSet(graph.registers());
            aliases.set(selector);
            List<Integer> comparisons = new ArrayList<>();
            Set<Integer> path = new HashSet<>();
            path.add(start);
            int pc = start + 1;
            int budget = 0;
            boolean copiedState = false;

            while (pc < graph.size() && budget++ < PATH_LIMIT && path.add(pc)) {
               Instruction instruction = graph.at(pc);
               Opcode op = instruction.getOpcode();
               if (op == Opcode.NOP) {
                  pc++;
               } else if (isConstant(op)) {
                  if (RegisterLiveness.writes(instruction).get(selector) && !copiedState) {
                     break;
                  }

                  aliases.andNot(RegisterLiveness.writes(instruction));
                  pc++;
               } else if (isCopy(op) || op == Opcode.SGET) {
                  // Register shuffling and stable field reads can sit between
                  // comparisons. Recovery separately proves their values and
                  // preserves throwing instructions and exception coverage.
                  // Integer copies may also carry the selector into later
                  // comparisons or copy it back; overwrites end that alias.
                  boolean selectorCopy = isIntegerCopy(op)
                     && aliases.get(((TwoRegisterInstruction)instruction).getRegisterB());
                  if (stateCopy(instruction, graph.at(start), selector, aliases)) {
                     if (comparisons.size() < 2) break;
                     copiedState = true;
                  }
                  if (RegisterLiveness.writes(instruction).get(selector) && !copiedState && !selectorCopy) break;
                  aliases.andNot(RegisterLiveness.writes(instruction));
                  if (selectorCopy) aliases.set(((TwoRegisterInstruction)instruction).getRegisterA());
                  pc++;
               } else if ((
                     !(op == Opcode.IF_EQ && instruction instanceof TwoRegisterInstruction two)
                        || !aliases.get(two.getRegisterA()) && !aliases.get(two.getRegisterB())
                  )
                  && (op != Opcode.IF_EQZ || !aliases.get(((OneRegisterInstruction)instruction).getRegisterA()))) {
                  if (!CodeGraph.isGoto(op)) {
                     break;
                  }

                  int back = graph.successors(pc).get(0);
                  if (xorEntry(graph, back, start, selector)) {
                     if (comparisons.size() < 2) {
                        break;
                     }

                     boolean exits = true;

                     for (int branch : comparisons) {
                        int target = graph.successors(branch).get(0);
                        if (path.contains(target) || target >= back && target <= start) {
                           exits = false;
                           break;
                        }
                     }

                     if (exits) {
                        result.addAll(comparisons);
                     }
                     break;
                  }

                  pc = back;
               } else {
                  if (copiedState) {
                     break;
                  }

                  comparisons.add(pc);
                  pc++;
               }
            }
            // Some layouts place the default XOR after the comparisons. Following
            // their default edges returns to it by fallthrough rather than a goto.
            if (pc == start && comparisons.size() >= 2
                  && comparisons.stream().noneMatch(branch -> path.contains(graph.successors(branch).get(0)))) {
               result.addAll(comparisons);
            }
         }
      }

      return result;
   }

   /** The decoded selector is copied back to the separate XOR state input on the default edge. */
   private static boolean stateCopy(Instruction instruction, Instruction xor, int selector, BitSet aliases) {
      Opcode op = instruction.getOpcode();
      if (!isIntegerCopy(op)) {
         return false;
      }

      TwoRegisterInstruction copy = (TwoRegisterInstruction)instruction;
      if (copy.getRegisterA() == selector || !aliases.get(copy.getRegisterB())) {
         return false;
      }

      if (xor instanceof ThreeRegisterInstruction three) {
         return copy.getRegisterA() == three.getRegisterB() || copy.getRegisterA() == three.getRegisterC();
      }

      return copy.getRegisterA() == ((TwoRegisterInstruction)xor).getRegisterB();
   }

   private static boolean xorEntry(CodeGraph graph, int target, int xor, int selector) {
      if (target <= xor && xor - target <= 4) {
         for (int i = target; i < xor; i++) {
            Instruction instruction = graph.at(i);
            if (instruction.getOpcode() != Opcode.NOP
               && (!isConstant(instruction.getOpcode()) || ((OneRegisterInstruction)instruction).getRegisterA() == selector)) {
               return false;
            }
         }

         return true;
      } else {
         return false;
      }
   }

   private static boolean isXor(Opcode op) {
      return op == Opcode.XOR_INT || op == Opcode.XOR_INT_2ADDR || op == Opcode.XOR_INT_LIT8 || op == Opcode.XOR_INT_LIT16;
   }

   private static boolean isConstant(Opcode op) {
      return op == Opcode.CONST || op == Opcode.CONST_4 || op == Opcode.CONST_16 || op == Opcode.CONST_HIGH16
         || op == Opcode.CONST_WIDE || op == Opcode.CONST_WIDE_16 || op == Opcode.CONST_WIDE_32 || op == Opcode.CONST_WIDE_HIGH16;
   }

   private static boolean isCopy(Opcode op) {
      return isIntegerCopy(op)
         || op == Opcode.MOVE_OBJECT || op == Opcode.MOVE_OBJECT_FROM16 || op == Opcode.MOVE_OBJECT_16
         || op == Opcode.MOVE_WIDE || op == Opcode.MOVE_WIDE_FROM16 || op == Opcode.MOVE_WIDE_16;
   }

   private static boolean isIntegerCopy(Opcode op) {
      return op == Opcode.MOVE || op == Opcode.MOVE_FROM16 || op == Opcode.MOVE_16;
   }
}
