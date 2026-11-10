package me.naptila.deobfuscator.transformers.np.analysis;

import java.util.ArrayDeque;
import java.util.ArrayList;
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

import org.jf.dexlib2.AccessFlags;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.Field;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.NarrowLiteralInstruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.instruction.ThreeRegisterInstruction;
import org.jf.dexlib2.iface.instruction.TwoRegisterInstruction;
import org.jf.dexlib2.iface.instruction.formats.ArrayPayload;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.TypeReference;

/** Indexes table users and rejects observed writes or escapes unless explicitly covered by a per-field assumption. */
public final class NpArrays {
   private NpArrays() {
   }

   public static Map<String, List<Short>> discover(DexContext dex, NpHelpers helpers) {
      return discover(dex, helpers, Map.of());
   }

   public static Map<String, List<Short>> discover(DexContext dex, NpHelpers helpers, Map<String, String> getters) {
      return discover(dex, helpers, getters, Set.of());
   }

   public static Map<String, List<Short>> discover(DexContext dex, NpHelpers helpers, Map<String, String> getters, Set<String> assumed) {
      Map<String, List<Short>> result = new HashMap<>();
      Map<String, List<Method>> users = tableUsers(dex, getters);

      for (Method method : dex.methods().values()) {
         if (method.getName().equals("<clinit>")
            && method.getImplementation() != null
            && AccessFlags.STATIC.isSet(method.getAccessFlags())
            && method.getImplementation().getTryBlocks().isEmpty()) {
            CodeGraph graph = new CodeGraph(method.getImplementation());
            Initializer initializer = Initializer.find(graph);
            if (initializer != null) {
               String sig = initializer.field();
               Field field = dex.findField(sig).orElse(null);
               if (field != null
                  && field.getType().equals("[S")
                  && field.getDefiningClass().equals(method.getDefiningClass())
                  && AccessFlags.PRIVATE.isSet(field.getAccessFlags())
                  && AccessFlags.STATIC.isSet(field.getAccessFlags())
                  && AccessFlags.FINAL.isSet(field.getAccessFlags())) {
                  BitSet initialAlias = new BitSet();
                  initialAlias.set(initializer.arrayRegister());
                  boolean safe = safeUses(method, sig, helpers, getters, initializer.store() + 1, initialAlias, assumed.contains(sig));
                  if (safe) {
                     for (Method user : users.getOrDefault(sig, List.of())) {
                        if (user.getImplementation() != null && !Signatures.of(user).equals(Signatures.of(method))) {
                           for (Instruction insn : user.getImplementation().getInstructions()) {
                              if (sig.equals(NpAnalysis.writtenField(insn))) {
                                 safe = false;
                              }
                           }

                           if (!safe) {
                              break;
                           }

                           if (!sig.equals(getters.get(Signatures.of(user))) && !safeUses(user, sig, helpers, getters, 0, new BitSet(), assumed.contains(sig))) {
                              safe = false;
                              break;
                           }
                        }
                     }

                     if (safe) {
                        result.put(sig, initializer.contents());
                     }
                  }
               }
            }
         }
      }

      return Map.copyOf(result);
   }

   private static Map<String, List<Method>> tableUsers(DexContext dex, Map<String, String> getters) {
      Map<String, List<Method>> users = new HashMap<>();

      for (Method method : dex.methods().values()) {
         if (method.getImplementation() != null) {
            Set<String> touched = new HashSet<>();

            for (Instruction instruction : method.getImplementation().getInstructions()) {
               String written = NpAnalysis.writtenField(instruction);
               if (written != null) {
                  touched.add(written);
               }

               if (instruction.getOpcode() == Opcode.SGET_OBJECT) {
                  touched.add(reference(instruction));
               }

               if (!getters.isEmpty()
                  && (instruction.getOpcode() == Opcode.INVOKE_STATIC || instruction.getOpcode() == Opcode.INVOKE_STATIC_RANGE)
                  && instruction instanceof ReferenceInstruction r
                  && r.getReference() instanceof MethodReference m) {
                  String field = getters.get(Signatures.of(m));
                  if (field != null) {
                     touched.add(field);
                  }
               }
            }

            for (String field : touched) {
               users.computeIfAbsent(field, key -> new ArrayList<>()).add(method);
            }
         }
      }

      return users;
   }

   private static boolean safeUses(
      Method method, String field, NpHelpers helpers, Map<String, String> getters, int start, BitSet initial, boolean assumeImmutable
   ) {
      boolean reads = !initial.isEmpty();

      for (Instruction i : method.getImplementation().getInstructions()) {
         if (i.getOpcode() == Opcode.SGET_OBJECT && reference(i).equals(field) || getter(i, field, getters)) {
            reads = true;
         }
      }

      if (!reads) {
         return true;
      }

      CodeGraph graph = new CodeGraph(method.getImplementation());
      BitSet[] before = new BitSet[graph.size()];
      ArrayDeque<Integer> work = new ArrayDeque<>();
      before[start] = (BitSet)initial.clone();
      work.add(start);
      int budget = Math.max(10000, graph.size() * 256);

      while (!work.isEmpty()) {
         if (--budget == 0) {
            return false;
         }

         int index = work.removeFirst();
         Instruction i = graph.at(index);
         Opcode op = i.getOpcode();
         if (field.equals(NpAnalysis.writtenField(i))) {
            return false;
         }

         BitSet in = before[index];
         BitSet out = (BitSet)in.clone();
         boolean move = op == Opcode.MOVE_OBJECT || op == Opcode.MOVE_OBJECT_FROM16 || op == Opcode.MOVE_OBJECT_16;
         boolean cast = op == Opcode.CHECK_CAST;
         boolean decoder = (op == Opcode.INVOKE_STATIC || op == Opcode.INVOKE_STATIC_RANGE)
            && i instanceof ReferenceInstruction r
            && r.getReference() instanceof MethodReference m
            && helpers.decoders.contains(Signatures.of(m));
         int[] regs = NpHelpers.registers(i);
         if (decoder) {
            int[] args = ConstantEvaluator.arguments(i);
            if (args.length != 4) {
               return false;
            }

            for (int a = 1; a < args.length; a++) {
               if (in.get(args[a])) {
                  return false;
               }
            }
         } else if (!move && !cast) {
            for (int r = 0; r < regs.length; r++) {
               if ((r != 0 || !op.setsRegister() || op.name.endsWith("/2addr"))
                  && in.get(regs[r])
                  && (!assumeImmutable || op.name.startsWith("aput") || op == Opcode.FILL_ARRAY_DATA)) {
                  return false;
               }
            }
         }

         if (op.setsRegister()) {
            out.clear(regs[0]);
            if (op.setsWideRegister()) {
               out.clear(regs[0] + 1);
            }
         }

         if (move && in.get(((TwoRegisterInstruction)i).getRegisterB())) {
            out.set(NpHelpers.reg(i));
         }

         // A successful cast keeps the same array. Track it so a subsequent write
         // cannot disappear from the immutability proof, even with a field assumption.
         if (cast && in.get(NpHelpers.reg(i))) {
            out.set(NpHelpers.reg(i));
         }

         if (op == Opcode.SGET_OBJECT && reference(i).equals(field)) {
            out.set(NpHelpers.reg(i));
         }

         if (op == Opcode.MOVE_RESULT_OBJECT && index > 0 && getter(graph.at(index - 1), field, getters)) {
            out.set(NpHelpers.reg(i));
         }

         for (int next : graph.successors(index)) {
            merge(before, next, out, work);
         }

         BitSet exceptional = (BitSet)in.clone();
         exceptional.or(out);

         for (int handler : graph.handlers(index)) {
            merge(before, handler, exceptional, work);
         }
      }

      return true;
   }

   public static boolean getter(Instruction instruction, String field, Map<String, String> getters) {
      return (instruction.getOpcode() == Opcode.INVOKE_STATIC || instruction.getOpcode() == Opcode.INVOKE_STATIC_RANGE)
         && instruction instanceof ReferenceInstruction r
         && r.getReference() instanceof MethodReference m
         && field.equals(getters.get(Signatures.of(m)));
   }

   private static void merge(BitSet[] states, int i, BitSet value, ArrayDeque<Integer> work) {
      if (states[i] == null) {
         states[i] = (BitSet)value.clone();
         work.add(i);
      } else {
         BitSet merged = (BitSet)states[i].clone();
         merged.or(value);
         if (!merged.equals(states[i])) {
            states[i] = merged;
            work.add(i);
         }
      }
   }

   private static String reference(Instruction i) {
      return i instanceof ReferenceInstruction r && r.getReference() instanceof FieldReference f ? Signatures.of(f) : "";
   }

   public record Initializer(String field, List<Short> contents, int arrayRegister, int store, BitSet prefix, boolean pure) {
      public static Initializer find(CodeGraph graph) {
         List<Integer> code = new ArrayList<>();

         for (int i = 0; i < graph.size(); i++) {
            if (!graph.isPayload(i) && graph.at(i).getOpcode() != Opcode.NOP) {
               code.add(i);
            }
         }

         if (code.size() < 5) {
            return null;
         }

         Instruction size = graph.at(code.get(0));
         Instruction allocation = graph.at(code.get(1));
         if (integer(size) && allocation.getOpcode() == Opcode.NEW_ARRAY) {
            TwoRegisterInstruction array = (TwoRegisterInstruction)allocation;
            if (((TypeReference)((ReferenceInstruction)allocation).getReference()).getType().equals("[S") && array.getRegisterB() == NpHelpers.reg(size)) {
               int length = ((NarrowLiteralInstruction)size).getNarrowLiteral();
               BitSet prefix = new BitSet();
               Instruction fill = graph.at(code.get(2));
               int storePosition;
               List<Short> contents;
               if (fill.getOpcode() == Opcode.FILL_ARRAY_DATA && NpHelpers.reg(fill) == array.getRegisterA()) {
                  int payload = graph.payloadIndex(code.get(2));
                  if (!(graph.at(payload) instanceof ArrayPayload data) || data.getElementWidth() != 2 || length != data.getArrayElements().size()) {
                     return null;
                  }

                  contents = data.getArrayElements().stream().map(Number::shortValue).toList();
                  prefix.set(payload);
                  storePosition = 3;
               } else {
                  if (code.size() < 7) {
                     return null;
                  }

                  Instruction index = fill;
                  Instruction value = graph.at(code.get(3));
                  Instruction put = graph.at(code.get(4));
                  if (length != 1
                     || !integer(index)
                     || !integer(value)
                     || ((NarrowLiteralInstruction)index).getNarrowLiteral() != 0
                     || put.getOpcode() != Opcode.APUT_SHORT) {
                     return null;
                  }

                  ThreeRegisterInstruction write = (ThreeRegisterInstruction)put;
                  if (write.getRegisterA() != NpHelpers.reg(value)
                     || write.getRegisterB() != array.getRegisterA()
                     || write.getRegisterC() != NpHelpers.reg(index)
                     || write.getRegisterA() == write.getRegisterB()
                     || write.getRegisterC() == write.getRegisterB()
                     || write.getRegisterA() == write.getRegisterC()) {
                     return null;
                  }

                  contents = List.of((short)((NarrowLiteralInstruction)value).getNarrowLiteral());
                  storePosition = 5;
               }

               int store = code.get(storePosition);
               if (graph.at(store).getOpcode() == Opcode.SPUT_OBJECT
                  && NpHelpers.reg(graph.at(store)) == array.getRegisterA()
                  && graph.at(code.get(code.size() - 1)).getOpcode() == Opcode.RETURN_VOID) {
                  prefix.set(0, store + 1);

                  for (int i = store + 1; i < graph.size(); i++) {
                     for (int target : graph.successors(i)) {
                        if (target <= store) {
                           return null;
                        }
                     }
                  }

                  String field = Signatures.of((FieldReference)((ReferenceInstruction)graph.at(store)).getReference());
                  return new Initializer(field, List.copyOf(contents), array.getRegisterA(), store, prefix, code.size() == storePosition + 2);
               } else {
                  return null;
               }
            } else {
               return null;
            }
         } else {
            return null;
         }
      }

      private static boolean integer(Instruction i) {
         return i.getOpcode() == Opcode.CONST || i.getOpcode() == Opcode.CONST_4 || i.getOpcode() == Opcode.CONST_16 || i.getOpcode() == Opcode.CONST_HIGH16;
      }
   }
}
