package me.naptila.deobfuscator.transformers.np.analysis;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.NarrowLiteralInstruction;
import org.jf.dexlib2.iface.instruction.OneRegisterInstruction;
import org.jf.dexlib2.iface.instruction.ThreeRegisterInstruction;
import org.jf.dexlib2.iface.instruction.TwoRegisterInstruction;
import org.jf.dexlib2.iface.instruction.WideLiteralInstruction;

/** Symbolic integer expressions shared by instruction simplification and helper-shape proofs. */
public final class IntegerExpressions {
   private static final Set<Opcode> OPERATIONS = EnumSet.noneOf(Opcode.class);
   private final Map<IntegerExpressions.Slot, IntegerExpressions.Expr> values = new HashMap<>();
   private final BitSet touched = new BitSet();
   private final BiFunction<Integer, Integer, IntegerExpressions.Literal> initial;
   private int operations;
   public int operations() { return operations; }
   private boolean seeded;
   public boolean seeded() { return seeded; }

   public IntegerExpressions(BiFunction<Integer, Integer, IntegerExpressions.Literal> initial) {
      this.initial = initial;
   }

   void symbolicInt(int register, int identity) {
      this.values.keySet().removeIf(k -> k.register() <= register && register < k.register() + k.bits() / 32);
      this.touched.set(register);
      this.values.put(new IntegerExpressions.Slot(register, 32), new IntegerExpressions.Var(identity, 32));
   }

   IntegerExpressions.Expr readInt(int register) {
      return this.get(register, 32);
   }

   private IntegerExpressions.Expr get(int register, int bits) {
      IntegerExpressions.Slot key = new IntegerExpressions.Slot(register, bits);
      IntegerExpressions.Expr existing = this.values.get(key);
      if (existing != null) {
         return existing;
      }

      if (!this.touched.get(register) && (bits != 64 || !this.touched.get(register + 1))) {
         IntegerExpressions.Expr value = this.initial.apply(register, bits);
         if (value != null) {
            this.seeded = true;
         }

         if (value == null) {
            value = new IntegerExpressions.Var(register, bits);
         }

         this.values.put(key, value);
         return value;
      } else {
         return null;
      }
   }

   public IntegerExpressions.Expr step(Instruction instruction) {
      Opcode op = instruction.getOpcode();
      String name = op.name;
      if (instruction instanceof OneRegisterInstruction one) {
         int a = one.getRegisterA();
         int bits = op.setsWideRegister() ? 64 : 32;
         IntegerExpressions.Expr value;
         if (op == Opcode.CONST_4 || op == Opcode.CONST_16 || op == Opcode.CONST || op == Opcode.CONST_HIGH16) {
            value = new IntegerExpressions.Literal(((NarrowLiteralInstruction)instruction).getNarrowLiteral(), 32);
         } else if (op == Opcode.CONST_WIDE || op == Opcode.CONST_WIDE_16 || op == Opcode.CONST_WIDE_32 || op == Opcode.CONST_WIDE_HIGH16) {
            value = new IntegerExpressions.Literal(((WideLiteralInstruction)instruction).getWideLiteral(), 64);
         } else if (op != Opcode.MOVE
            && op != Opcode.MOVE_FROM16
            && op != Opcode.MOVE_16
            && op != Opcode.MOVE_WIDE
            && op != Opcode.MOVE_WIDE_FROM16
            && op != Opcode.MOVE_WIDE_16) {
            if (!OPERATIONS.contains(op)) {
               return null;
            }

            String operation = name.substring(0, name.indexOf(45));
            IntegerExpressions.Expr left;
            IntegerExpressions.Expr right;
            if (operation.equals("neg") || operation.equals("not")) {
               left = this.get(((TwoRegisterInstruction)instruction).getRegisterB(), bits);
               right = new IntegerExpressions.Literal(operation.equals("neg") ? 0L : -1L, bits);
               if (operation.equals("neg")) {
                  IntegerExpressions.Expr old = left;
                  left = right;
                  right = old;
                  operation = "sub";
               } else {
                  operation = "xor";
               }
            } else if (instruction instanceof ThreeRegisterInstruction r) {
               left = this.get(r.getRegisterB(), bits);
               right = this.get(r.getRegisterC(), bits);
            } else if (instruction instanceof NarrowLiteralInstruction literal) {
               left = this.get(((TwoRegisterInstruction)instruction).getRegisterB(), bits);
               right = new IntegerExpressions.Literal(literal.getNarrowLiteral(), bits);
            } else {
               if (!name.endsWith("/2addr")) {
                  return null;
               }

               left = this.get(a, bits);
               right = this.get(((TwoRegisterInstruction)instruction).getRegisterB(), bits);
            }

            if (operation.equals("rsub")) {
               IntegerExpressions.Expr old = left;
               left = right;
               right = old;
               operation = "sub";
            }

            if (left == null || right == null) {
               return null;
            }

            value = new IntegerExpressions.Binary(operation, left, right, bits);
            this.operations++;
         } else {
            value = this.get(((TwoRegisterInstruction)instruction).getRegisterB(), bits);
         }

         if (value == null) {
            return null;
         }

         int words = bits / 32;
         this.values.keySet().removeIf(k -> k.register() < a + words && k.register() + k.bits() / 32 > a);
         this.touched.set(a, a + words);
         this.values.put(new IntegerExpressions.Slot(a, bits), value);
         return value;
      } else {
         return null;
      }
   }

   public static IntegerExpressions.Expr simplify(IntegerExpressions.Expr expression) {
      int bits = expression.bits();
      Map<IntegerExpressions.Var, Long> terms = new LinkedHashMap<>();
      long[] constant = new long[]{0L};
      if (linear(expression, 1L, terms, constant)) {
         terms.replaceAll((k, v) -> truncate(v, bits));
         terms.values().removeIf(v -> v == 0L);
         List<IntegerExpressions.Var> positive = new ArrayList<>();
         List<IntegerExpressions.Var> negative = new ArrayList<>();

         for (Map.Entry<IntegerExpressions.Var, Long> e : terms.entrySet()) {
            if (e.getValue() == 1L) {
               positive.add(e.getKey());
            } else {
               if (e.getValue() != -1L) {
                  return null;
               }

               negative.add(e.getKey());
            }
         }

         long value = truncate(constant[0], bits);
         if (terms.isEmpty()) {
            return new IntegerExpressions.Literal(value, bits);
         } else if (terms.size() == 1 && positive.size() == 1) {
            return value == 0L ? positive.get(0) : new IntegerExpressions.Binary("add", positive.get(0), new IntegerExpressions.Literal(value, bits), bits);
         } else if (terms.size() == 1 && negative.size() == 1) {
            return new IntegerExpressions.Binary("sub", new IntegerExpressions.Literal(value, bits), negative.get(0), bits);
         } else if (value != 0L) {
            return null;
         } else if (positive.size() == 2 && negative.isEmpty()) {
            return new IntegerExpressions.Binary("add", positive.get(0), positive.get(1), bits);
         } else {
            return positive.size() == 1 && negative.size() == 1 ? new IntegerExpressions.Binary("sub", positive.get(0), negative.get(0), bits) : null;
         }
      } else {
         Set<IntegerExpressions.Var> inputs = new LinkedHashSet<>();
         if (bitwise(expression, inputs) && inputs.size() <= 2) {
            List<IntegerExpressions.Var> vars = new ArrayList<>(inputs);
            if (vars.isEmpty()) {
               return new IntegerExpressions.Literal(evaluateBits(expression, vars, 0), bits);
            }
            IntegerExpressions.Var a = vars.get(0);
            long[] table = new long[1 << vars.size()];

            for (int assignment = 0; assignment < table.length; assignment++) {
               table[assignment] = evaluateBits(expression, vars, assignment);
            }

            if (vars.size() == 1) {
               long zero = table[0];
               long ones = table[1];
               if (zero == ones) {
                  return new IntegerExpressions.Literal(zero, bits);
               }

               if (ones == truncate(~zero, bits)) {
                  return zero == 0L ? a : new IntegerExpressions.Binary("xor", a, new IntegerExpressions.Literal(zero, bits), bits);
               }

               if (zero == 0L) {
                  return new IntegerExpressions.Binary("and", a, new IntegerExpressions.Literal(ones, bits), bits);
               }

               if (ones == -1L) {
                  return new IntegerExpressions.Binary("or", a, new IntegerExpressions.Literal(zero, bits), bits);
               }
            } else {
               for (String op : List.of("and", "or", "xor")) {
                  IntegerExpressions.Expr candidate = new IntegerExpressions.Binary(op, a, vars.get(1), bits);
                  boolean equal = true;

                  for (int assignment = 0; assignment < 4; assignment++) {
                     equal &= table[assignment] == evaluateBits(candidate, vars, assignment);
                  }

                  if (equal) {
                     return candidate;
                  }
               }
            }

            return null;
         } else {
            return null;
         }
      }
   }

   private static boolean linear(IntegerExpressions.Expr e, long sign, Map<IntegerExpressions.Var, Long> terms, long[] constant) {
      if (e instanceof IntegerExpressions.Var v) {
         terms.merge(v, sign, Long::sum);
         return true;
      } else if (e instanceof IntegerExpressions.Literal v) {
         constant[0] += sign * v.value();
         return true;
      } else {
         IntegerExpressions.Binary b = (IntegerExpressions.Binary)e;
         return !b.op().equals("add") && !b.op().equals("sub")
            ? false
            : linear(b.left(), sign, terms, constant) && linear(b.right(), b.op().equals("add") ? sign : -sign, terms, constant);
      }
   }

   private static boolean bitwise(IntegerExpressions.Expr e, Set<IntegerExpressions.Var> vars) {
      if (e instanceof IntegerExpressions.Var v) {
         vars.add(v);
         return true;
      } else {
         if (e instanceof IntegerExpressions.Literal) {
            return true;
         }

         IntegerExpressions.Binary b = (IntegerExpressions.Binary)e;
         return Set.of("and", "or", "xor").contains(b.op()) && bitwise(b.left(), vars) && bitwise(b.right(), vars);
      }
   }

   private static long evaluateBits(IntegerExpressions.Expr e, List<IntegerExpressions.Var> vars, int assignment) {
      if (e instanceof IntegerExpressions.Literal v) {
         return v.value();
      } else if (e instanceof IntegerExpressions.Var v) {
         return (assignment & 1 << vars.indexOf(v)) == 0 ? 0L : -1L;
      } else {
         IntegerExpressions.Binary b = (IntegerExpressions.Binary)e;
         long left = evaluateBits(b.left(), vars, assignment);
         long right = evaluateBits(b.right(), vars, assignment);

         return truncate(switch (b.op()) {
            case "and" -> left & right;
            case "or" -> left | right;
            case "xor" -> left ^ right;
            default -> throw new IllegalArgumentException();
         }, e.bits());
      }
   }

   static long truncate(long value, int bits) {
      return bits == 32 ? (int)value : value;
   }

   static {
      for (Opcode op : Opcode.values()) {
         if (op.name.matches("(?:add|sub|rsub|and|or|xor|neg|not)-(?:int|long)(?:/.*)?")) {
            OPERATIONS.add(op);
         }
      }
   }

   public record Binary(String op, IntegerExpressions.Expr left, IntegerExpressions.Expr right, int bits) implements IntegerExpressions.Expr {
   }

   public sealed interface Expr permits IntegerExpressions.Var, IntegerExpressions.Literal, IntegerExpressions.Binary {
      int bits();
   }

   public record Literal(long value, int bits) implements IntegerExpressions.Expr {
      public Literal {
         value = IntegerExpressions.truncate(value, bits);
      }
   }

   private record Slot(int register, int bits) {
   }

   public record Var(int register, int bits) implements IntegerExpressions.Expr {
   }
}
