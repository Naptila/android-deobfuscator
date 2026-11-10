package me.naptila.deobfuscator.dex;

import java.util.List;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.BuilderInstruction;
import org.jf.dexlib2.builder.BuilderOffsetInstruction;
import org.jf.dexlib2.builder.Label;
import org.jf.dexlib2.builder.MutableMethodImplementation;
import org.jf.dexlib2.builder.instruction.BuilderInstruction21t;
import org.jf.dexlib2.builder.instruction.BuilderInstruction22t;
import org.jf.dexlib2.builder.instruction.BuilderInstruction30t;

final class BranchRelaxation {
   private BranchRelaxation() {
   }

   static void run(MutableMethodImplementation code) {
      boolean changed;
      do {
         changed = false;
         List<BuilderInstruction> instructions = code.getInstructions();

         for (int i = instructions.size() - 1; i >= 0; i--) {
            BuilderInstruction instruction = instructions.get(i);
            if (CodeGraph.isIf(instruction.getOpcode())) {
               BuilderOffsetInstruction branch = (BuilderOffsetInstruction)instruction;
               int offset = branch.getTarget().getCodeAddress() - instruction.getLocation().getCodeAddress();
               if (offset < -32768 || offset > 32767 || offset == 0) {
                  Label target = branch.getTarget();
                  Label fallthrough = code.newLabelForIndex(i + 1);
                  Opcode inverse = inverse(instruction.getOpcode());
                  BuilderInstruction replacement;
                  if (instruction instanceof BuilderInstruction21t b) {
                     replacement = new BuilderInstruction21t(inverse, b.getRegisterA(), fallthrough);
                  } else {
                     BuilderInstruction22t b = (BuilderInstruction22t)instruction;
                     replacement = new BuilderInstruction22t(inverse, b.getRegisterA(), b.getRegisterB(), fallthrough);
                  }

                  code.replaceInstruction(i, replacement);
                  code.addInstruction(i + 1, new BuilderInstruction30t(Opcode.GOTO_32, target));
                  changed = true;
               }
            }
         }
      } while (changed);
   }

   private static Opcode inverse(Opcode op) {
      return switch (op) {
         case IF_EQ -> Opcode.IF_NE;
         case IF_NE -> Opcode.IF_EQ;
         case IF_LT -> Opcode.IF_GE;
         case IF_GE -> Opcode.IF_LT;
         case IF_GT -> Opcode.IF_LE;
         case IF_LE -> Opcode.IF_GT;
         case IF_EQZ -> Opcode.IF_NEZ;
         case IF_NEZ -> Opcode.IF_EQZ;
         case IF_LTZ -> Opcode.IF_GEZ;
         case IF_GEZ -> Opcode.IF_LTZ;
         case IF_GTZ -> Opcode.IF_LEZ;
         case IF_LEZ -> Opcode.IF_GTZ;
         default -> throw new IllegalArgumentException("Not a conditional: " + op);
      };
   }
}
