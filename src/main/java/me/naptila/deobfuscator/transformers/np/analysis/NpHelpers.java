package me.naptila.deobfuscator.transformers.np.analysis;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.ConstantEvaluator;
import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.Signatures;
import me.naptila.deobfuscator.transformers.np.support.ProxyAccess;
import me.naptila.deobfuscator.transformers.np.strings.NpStringCalls;

import org.jf.dexlib2.AccessFlags;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Field;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.NarrowLiteralInstruction;
import org.jf.dexlib2.iface.instruction.OneRegisterInstruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.instruction.ThreeRegisterInstruction;
import org.jf.dexlib2.iface.instruction.TwoRegisterInstruction;
import org.jf.dexlib2.iface.instruction.VariableRegisterInstruction;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.TypeReference;

/** Recognized helper semantics and separate deletion proofs. Bootstrap analysis alone may extend these facts. */
public final class NpHelpers {
   final Set<String> hashes = new HashSet<>();
   final Set<String> decoders = new HashSet<>();
   final Set<String> owners = new HashSet<>();
   final Set<String> removableDecoders = new HashSet<>();
   final Set<String> removableHashes = new HashSet<>();
   final Set<String> removableGuards = new HashSet<>();
   final Map<String, NpHelpers.Guard> guards = new HashMap<>();

   private final Set<String> hashesView = java.util.Collections.unmodifiableSet(hashes);
   public Set<String> hashes() { return hashesView; }
   private final Set<String> decodersView = java.util.Collections.unmodifiableSet(decoders);
   public Set<String> decoders() { return decodersView; }
   private final Set<String> ownersView = java.util.Collections.unmodifiableSet(owners);
   public Set<String> owners() { return ownersView; }
   private final Set<String> removableDecodersView = java.util.Collections.unmodifiableSet(removableDecoders);
   public Set<String> removableDecoders() { return removableDecodersView; }
   private final Set<String> removableHashesView = java.util.Collections.unmodifiableSet(removableHashes);
   public Set<String> removableHashes() { return removableHashesView; }
   private final Set<String> removableGuardsView = java.util.Collections.unmodifiableSet(removableGuards);
   public Set<String> removableGuards() { return removableGuardsView; }
   private final Map<String, Guard> guardsView = java.util.Collections.unmodifiableMap(guards);
   public Map<String, Guard> guards() { return guardsView; }

   NpHelpers(DexContext dex) {
      for (ClassDef cls : dex.classes().values()) {
         if ("Ljava/lang/Object;".equals(cls.getSuperclass()) && cls.getInterfaces().isEmpty()) {
            boolean initializer = false;

            for (Method m : cls.getMethods()) {
               if (m.getName().equals("<clinit>")) {
                  initializer = true;
               }
            }

            if (!initializer) {
               for (Method m : cls.getMethods()) {
                  if (m.getImplementation() != null
                     && AccessFlags.STATIC.isSet(m.getAccessFlags())
                     && !AccessFlags.SYNCHRONIZED.isSet(m.getAccessFlags())
                     && !AccessFlags.DECLARED_SYNCHRONIZED.isSet(m.getAccessFlags())
                     && m.getImplementation().getTryBlocks().isEmpty()) {
                     List<Instruction> code = new ArrayList<>();
                     m.getImplementation().getInstructions().forEach(code::add);
                     String sig = Signatures.of(m);
                     if (descriptor(m).equals("(Ljava/lang/Object;)I")
                        && m.getImplementation().getRegisterCount() == 2
                        && fingerprint(code).equals(List.of("invoke-virtual [1] Ljava/lang/Object;->hashCode()I", "move-result [0]", "return [0]"))) {
                        this.hashes.add(sig);
                     }

                     if (descriptor(m).equals("([SIII)Ljava/lang/String;")
                        && m.getImplementation().getRegisterCount() == 7
                        && fingerprint(code)
                           .equals(
                              List.of(
                                 "new-array [1, 5] [C",
                                 "const/4 [0] #0",
                                 "if-ge [0, 5]",
                                 "add-int [2, 4, 0]",
                                 "aget-short [2, 3, 2]",
                                 "xor-int/2addr [2, 6]",
                                 "int-to-char [2, 2]",
                                 "aput-char [2, 1, 0]",
                                 "add-int/lit8 [0, 0] #1",
                                 "goto []",
                                 "new-instance [0] Ljava/lang/String;",
                                 "invoke-direct [0, 1] Ljava/lang/String;-><init>([C)V",
                                 "return-object [0]"
                              )
                           )) {
                        CodeGraph graph = new CodeGraph(m.getImplementation());
                        if (graph.successors(2).get(0) == 10 && graph.successors(9).get(0) == 2) {
                           this.decoders.add(sig);
                           if (AccessFlags.PUBLIC.isSet(cls.getAccessFlags()) && AccessFlags.PUBLIC.isSet(m.getAccessFlags())) {
                              this.removableDecoders.add(sig);
                           }
                        }
                     }

                     if (descriptor(m).equals("()I")
                        && m.getImplementation().getRegisterCount() == 2
                        && code.size() == 4
                        && code.get(0).getOpcode() == Opcode.CONST
                        && reg(code.get(0)) == 0
                        && code.get(1).getOpcode() == Opcode.SGET
                        && reg(code.get(1)) == 1
                        && code.get(2).getOpcode() == Opcode.XOR_INT_2ADDR
                        && Arrays.equals(registers(code.get(2)), new int[]{0, 1})
                        && code.get(3).getOpcode() == Opcode.RETURN
                        && reg(code.get(3)) == 0) {
                        this.guards
                           .put(
                              sig,
                              new NpHelpers.Guard(
                                 Signatures.of((FieldReference)((ReferenceInstruction)code.get(1)).getReference()),
                                 ((NarrowLiteralInstruction)code.get(0)).getNarrowLiteral()
                              )
                           );
                     }
                  }
               }
            }
         }
      }

      for (String hash : this.hashes) {
         String owner = hash.substring(0, hash.indexOf("->"));
         if (this.decoders.stream().anyMatch(s -> s.startsWith(owner + "->")) && this.guards.keySet().stream().anyMatch(s -> s.startsWith(owner + "->"))) {
            this.owners.add(owner);
         }
      }

      this.hashes.removeIf(s -> !this.owners.contains(s.substring(0, s.indexOf("->"))));
      this.decoders.removeIf(s -> !this.owners.contains(s.substring(0, s.indexOf("->"))));
      this.removableDecoders.retainAll(this.decoders);
      this.guards.keySet().removeIf(s -> !this.owners.contains(s.substring(0, s.indexOf("->"))));
      this.removableHashes.addAll(this.hashes);
      this.removableGuards.addAll(this.guards.keySet());

      for (ClassDef cls : dex.classes().values()) {
         for (Method m : cls.getMethods()) {
            if (m.getImplementation() != null
               && AccessFlags.STATIC.isSet(m.getAccessFlags())
               && !AccessFlags.SYNCHRONIZED.isSet(m.getAccessFlags())
               && !AccessFlags.DECLARED_SYNCHRONIZED.isSet(m.getAccessFlags())
               && m.getImplementation().getTryBlocks().isEmpty()) {
               String sig = Signatures.of(m);
               if (NpHelpers.hash(m)) {
                  this.hashes.add(sig);
                  if (NpStringCalls.initializationSafe(dex, cls.getType(), "")) {
                     this.removableHashes.add(sig);
                  }
               }

               NpHelpers.Guard guard = NpHelpers.guard(m);
               if (guard != null) {
                  Field field = dex.fields().get(guard.field());
                  if (field != null && ProxyAccess.member(dex, field, cls.getType(), false)) {
                     this.guards.put(sig, guard);
                     if (NpStringCalls.initializationSafe(dex, cls.getType(), "") && NpStringCalls.initializationSafe(dex, field.getDefiningClass(), "")) {
                        this.removableGuards.add(sig);
                     }
                  }
               }
            }
         }
      }
   }

   public static String descriptor(Method m) {
      return "(" + String.join("", m.getParameterTypes()) + ")" + m.getReturnType();
   }

   public static int reg(Instruction i) {
      return ((OneRegisterInstruction)i).getRegisterA();
   }

   public static int[] registers(Instruction i) {
      if (i instanceof VariableRegisterInstruction) {
         return ConstantEvaluator.arguments(i);
      } else if (i instanceof ThreeRegisterInstruction t) {
         return new int[]{t.getRegisterA(), t.getRegisterB(), t.getRegisterC()};
      } else if (i instanceof TwoRegisterInstruction t) {
         return new int[]{t.getRegisterA(), t.getRegisterB()};
      } else {
         return i instanceof OneRegisterInstruction t ? new int[]{t.getRegisterA()} : new int[0];
      }
   }

   private static List<String> fingerprint(List<Instruction> code) {
      List<String> result = new ArrayList<>();

      for (Instruction i : code) {
         String s = i.getOpcode().name + " " + Arrays.toString(registers(i));
         if (i instanceof NarrowLiteralInstruction n) {
            s = s + " #" + n.getNarrowLiteral();
         }

         if (i instanceof ReferenceInstruction r) {
            if (r.getReference() instanceof MethodReference m) {
               s = s + " " + Signatures.of(m);
            } else if (r.getReference() instanceof TypeReference t) {
               s = s + " " + t.getType();
            } else {
               s = s + " ?";
            }
         }

         result.add(s);
      }

      return result;
   }

   public record Guard(String field, int key) {
   }

   static List<Instruction> straight(Method method) {
      CodeGraph graph = new CodeGraph(method.getImplementation());
      if (graph.size() > 128) {
         return List.of();
      }

      List<Instruction> result = new ArrayList<>();
      Set<Integer> visited = new HashSet<>();
      int pc = 0;

      while (pc < graph.size() && visited.add(pc)) {
         Instruction i = graph.at(pc);
         Opcode op = i.getOpcode();
         if (CodeGraph.isGoto(op)) {
            pc = graph.successors(pc).get(0);
         } else if (op == Opcode.NOP) {
            pc++;
         } else {
            if (CodeGraph.isIf(op) || CodeGraph.isSwitch(op) || graph.isPayload(pc)) {
               return List.of();
            }

            result.add(i);
            if (op.name.startsWith("return")) {
               return result;
            }

            if (!op.canContinue()) {
               return List.of();
            }

            pc++;
         }
      }

      return List.of();
   }

   static boolean hash(Method method) {
      if (!NpHelpers.descriptor(method).equals("(Ljava/lang/Object;)I")) {
         return false;
      }

      List<Instruction> code = straight(method);
      BitSet parameter = new BitSet();
      BitSet result = new BitSet();
      parameter.set(method.getImplementation().getRegisterCount() - 1);
      boolean invoked = false;
      boolean pending = false;

      for (Instruction i : code) {
         Opcode op = i.getOpcode();
         if (op != Opcode.MOVE_OBJECT && op != Opcode.MOVE_OBJECT_16 && op != Opcode.MOVE_OBJECT_FROM16) {
            if (op != Opcode.MOVE && op != Opcode.MOVE_16 && op != Opcode.MOVE_FROM16) {
               if ((op == Opcode.INVOKE_VIRTUAL || op == Opcode.INVOKE_VIRTUAL_RANGE)
                  && i instanceof ReferenceInstruction r
                  && r.getReference() instanceof MethodReference m
                  && Signatures.of(m).equals("Ljava/lang/Object;->hashCode()I")
                  && !invoked) {
                  int[] args = ConstantEvaluator.arguments(i);
                  if (args.length == 1 && parameter.get(args[0])) {
                     pending = true;
                     invoked = true;
                     continue;
                  }

                  return false;
               }

               if (op != Opcode.MOVE_RESULT || !pending) {
                  if (op != Opcode.RETURN) {
                     return false;
                  }

                  return invoked && result.get(NpHelpers.reg(i));
               }

               result.set(NpHelpers.reg(i));
               parameter.clear(NpHelpers.reg(i));
            } else {
               TwoRegisterInstruction move = (TwoRegisterInstruction)i;
               if (!result.get(move.getRegisterB())) {
                  return false;
               }

               result.set(move.getRegisterA());
               parameter.clear(move.getRegisterA());
            }
         } else {
            TwoRegisterInstruction move = (TwoRegisterInstruction)i;
            if (!parameter.get(move.getRegisterB())) {
               return false;
            }

            parameter.set(move.getRegisterA());
            result.clear(move.getRegisterA());
         }

         pending = false;
      }

      return false;
   }

   static NpHelpers.Guard guard(Method method) {
      if (!NpHelpers.descriptor(method).equals("()I")) {
         return null;
      }

      IntegerExpressions expressions = new IntegerExpressions((register, bits) -> null);
      FieldReference field = null;

      for (Instruction i : straight(method)) {
         if (i.getOpcode() == Opcode.SGET && i instanceof ReferenceInstruction r && r.getReference() instanceof FieldReference f) {
            if (field != null || !f.getType().equals("I")) {
               return null;
            }

            field = f;
            expressions.symbolicInt(NpHelpers.reg(i), -1);
         } else {
            if (i.getOpcode() == Opcode.RETURN) {
               if (field == null) {
                  return null;
               }

               IntegerExpressions.Expr value = expressions.readInt(NpHelpers.reg(i));
               if (value == null) {
                  return null;
               }

               if (IntegerExpressions.simplify(value) instanceof IntegerExpressions.Binary b
                  && b.op().equals("xor")
                  && b.left() instanceof IntegerExpressions.Var v
                  && v.register() == -1
                  && v.bits() == 32
                  && b.right() instanceof IntegerExpressions.Literal literal) {
                  return new NpHelpers.Guard(Signatures.of(field), (int)literal.value());
               }

               return null;
            }

            if (expressions.step(i) == null) {
               return null;
            }
         }
      }

      return null;
   }
}
