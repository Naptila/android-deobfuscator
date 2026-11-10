package me.naptila.deobfuscator.transformers.np.analysis;

import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.RegisterLiveness;
import me.naptila.deobfuscator.dex.Signatures;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.NarrowLiteralInstruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.instruction.TwoRegisterInstruction;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.Reference;
import org.jf.dexlib2.iface.reference.TypeReference;

/** Proves the short-array XOR decoder loop, including stride, bounds and absence of unmodeled effects. */
final class NpDecoderShape {
   private NpDecoderShape() {}
   static boolean matches(Method method) {
      if (!NpHelpers.descriptor(method).equals("([SIII)Ljava/lang/String;")) {
         return false;
      }

      CodeGraph graph = new CodeGraph(method.getImplementation());
      if (graph.size() <= 128 && method.getImplementation().getTryBlocks().isEmpty()) {
         int first = graph.registers() - 4;
         NpDecoderShape.State entry = new NpDecoderShape.State();
         entry.values.put(first, "table");
         entry.values.put(first + 1, "start");
         entry.values.put(first + 2, "length");
         entry.values.put(first + 3, "key");
         int header = walk(graph, 0, -1, entry, 0);
         if (header >= 0 && entry.allocations == 1 && graph.at(header) instanceof TwoRegisterInstruction condition) {
            Opcode op = graph.at(header).getOpcode();
            if ((op == Opcode.IF_GE || op == Opcode.IF_LT)
               && Objects.equals(entry.get(condition.getRegisterA()), 0)
               && "length".equals(entry.get(condition.getRegisterB()))) {
               int index = condition.getRegisterA();
               entry.values.put(index, "index");
               NpDecoderShape.State body = new NpDecoderShape.State(entry);
               int target = graph.successors(header).get(0);
               int bodyStart = op == Opcode.IF_GE ? header + 1 : target;
               int exitStart = op == Opcode.IF_GE ? target : header + 1;
               if (walk(graph, bodyStart, header, body, 1) == header
                  && body.loads == 1
                  && body.stores == 1
                  && Objects.equals(body.get(index), add("index", 1, 1))) {
                  RegisterLiveness live = new RegisterLiveness(graph);

                  for (int r = 0; r < graph.registers(); r++) {
                     if (r != index && live.liveBefore(header, r) && (entry.get(r) == null || !entry.get(r).equals(body.get(r)))) {
                        return false;
                     }
                  }

                  NpDecoderShape.State exit = new NpDecoderShape.State(entry);
                  int end = walk(graph, exitStart, -1, exit, 2);
                  return end >= 0
                     && graph.at(end).getOpcode() == Opcode.RETURN_OBJECT
                     && exit.constructed
                     && "string".equals(exit.get(NpHelpers.reg(graph.at(end))));
               } else {
                  return false;
               }
            } else {
               return false;
            }
         } else {
            return false;
         }
      } else {
         return false;
      }
   }

   private static int walk(CodeGraph graph, int pc, int stop, NpDecoderShape.State s, int phase) {
      Set<Integer> seen = new HashSet<>();
      int budget = 0;

      while (budget < 128) {
         if (pc == stop) {
            return pc;
         }

         if (pc >= 0 && pc < graph.size() && seen.add(pc) && !graph.isPayload(pc)) {
            Instruction i = graph.at(pc);
            Opcode op = i.getOpcode();
            if (!CodeGraph.isIf(op) && !op.name.startsWith("return")) {
               if (CodeGraph.isGoto(op)) {
                  pc = graph.successors(pc).get(0);
               } else {
                  if (!step(i, s, phase)) {
                     return -1;
                  }

                  pc++;
               }

               budget++;
               continue;
            }

            return pc;
         }

         return -1;
      }

      return -1;
   }

   private static boolean step(Instruction i, NpDecoderShape.State s, int phase) {
      Opcode op = i.getOpcode();
      int[] r = NpHelpers.registers(i);
      if (op == Opcode.NOP) {
         return true;
      }

      if (op == Opcode.CONST || op == Opcode.CONST_4 || op == Opcode.CONST_16 || op == Opcode.CONST_HIGH16) {
         s.values.put(r[0], ((NarrowLiteralInstruction)i).getNarrowLiteral());
         return true;
      }

      if (op != Opcode.MOVE
         && op != Opcode.MOVE_FROM16
         && op != Opcode.MOVE_16
         && op != Opcode.MOVE_OBJECT
         && op != Opcode.MOVE_OBJECT_FROM16
         && op != Opcode.MOVE_OBJECT_16) {
         if (op == Opcode.NEW_ARRAY && phase == 0 && s.allocations++ == 0 && reference(i).equals("[C") && "length".equals(s.get(r[1]))) {
            return s.put(r[0], "chars");
         }

         if (op == Opcode.AGET_SHORT && phase == 1 && s.loads++ == 0 && "table".equals(s.get(r[1])) && Objects.equals(s.get(r[2]), add("start", "index", 1))) {
            return s.put(r[0], "short");
         }

         if (op == Opcode.INT_TO_CHAR && phase == 1 && s.get(r[1]) != null) {
            return s.put(r[0], new NpDecoderShape.Char(s.get(r[1])));
         }

         if (op == Opcode.APUT_CHAR && phase == 1 && s.stores++ == 0) {
            return "chars".equals(s.get(r[1])) && "index".equals(s.get(r[2])) && new NpDecoderShape.Char(xor("short", "key")).equals(s.get(r[0]));
         }

         if (op == Opcode.NEW_INSTANCE && phase == 2 && !s.allocatedString && reference(i).equals("Ljava/lang/String;")) {
            s.allocatedString = true;
            return s.put(r[0], "string");
         }

         if ((op == Opcode.INVOKE_DIRECT || op == Opcode.INVOKE_DIRECT_RANGE)
            && phase == 2
            && !s.constructed
            && reference(i).equals("Ljava/lang/String;-><init>([C)V")
            && r.length == 2
            && "string".equals(s.get(r[0]))
            && "chars".equals(s.get(r[1]))) {
            s.constructed = true;
            return true;
         }

         String name = op.name;
         if (!name.startsWith("add-int") && !name.startsWith("sub-int") && !name.startsWith("rsub-int") && !name.startsWith("xor-int")) {
            return false;
         }

         Object a;
         Object b;
         if (i instanceof NarrowLiteralInstruction n) {
            a = s.get(r[1]);
            b = n.getNarrowLiteral();
         } else if (r.length == 2) {
            a = s.get(r[0]);
            b = s.get(r[1]);
         } else {
            a = s.get(r[1]);
            b = s.get(r[2]);
         }

         return a != null && b != null
            ? s.put(r[0], name.startsWith("xor") ? xor(a, b) : (name.startsWith("rsub") ? add(b, a, -1) : add(a, b, name.startsWith("sub") ? -1 : 1)))
            : false;
      } else {
         return s.put(r[0], s.get(r[1]));
      }
   }

   private static String reference(Instruction i) {
      Reference ref = ((ReferenceInstruction)i).getReference();
      return ref instanceof TypeReference t ? t.getType() : (ref instanceof MethodReference m ? Signatures.of(m) : "");
   }

   private static Object add(Object a, Object b, int sign) {
      Map<Object, Integer> terms = new HashMap<>();
      terms(a, 1, terms);
      terms(b, sign, terms);
      terms.values().removeIf(n -> n == 0);
      if (terms.isEmpty()) {
         return 0;
      }

      if (terms.size() == 1) {
         if (terms.containsKey("one")) {
            return terms.get("one");
         }

         Map.Entry<Object, Integer> term = terms.entrySet().iterator().next();
         if (term.getValue() == 1) {
            return term.getKey();
         }
      }

      return new NpDecoderShape.Sum(Map.copyOf(terms));
   }

   private static void terms(Object x, int sign, Map<Object, Integer> out) {
      if (x instanceof NpDecoderShape.Sum sum) {
         sum.terms().forEach((key, nx) -> out.merge(key, sign * nx, Integer::sum));
      } else {
         out.merge(x instanceof Integer ? "one" : x, x instanceof Integer n ? sign * n : sign, Integer::sum);
      }
   }

   private static Object xor(Object a, Object b) {
      return new NpDecoderShape.Xor(new HashSet<>(List.of(a, b)));
   }

   private record Char(Object value) {
   }

   private static final class State {
      final Map<Integer, Object> values = new HashMap<>();
      int allocations;
      int loads;
      int stores;
      boolean allocatedString;
      boolean constructed;

      State() {
      }

      State(NpDecoderShape.State other) {
         this.values.putAll(other.values);
      }

      Object get(int r) {
         return this.values.get(r);
      }

      boolean put(int r, Object value) {
         if (value == null) {
            return false;
         }

         this.values.put(r, value);
         return true;
      }
   }

   private record Sum(Map<Object, Integer> terms) {
   }

   private record Xor(Set<Object> terms) {
   }
}
