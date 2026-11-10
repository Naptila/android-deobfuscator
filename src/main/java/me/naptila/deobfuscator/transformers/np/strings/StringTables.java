package me.naptila.deobfuscator.transformers.np.strings;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.ConstantEvaluator;
import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.DexFinalizer;
import me.naptila.deobfuscator.dex.ExceptionEdits;
import me.naptila.deobfuscator.dex.FieldReferences;
import me.naptila.deobfuscator.dex.MethodContext;
import me.naptila.deobfuscator.dex.RegisterLiveness;
import me.naptila.deobfuscator.dex.Signatures;
import me.naptila.deobfuscator.transformers.np.analysis.NpArrays;
import me.naptila.deobfuscator.transformers.np.analysis.NpArrays.Initializer;
import me.naptila.deobfuscator.transformers.np.analysis.NpHelpers;
import me.naptila.deobfuscator.transformers.np.analysis.NpModel;

import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Field;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.instruction.TwoRegisterInstruction;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.immutable.ImmutableClassDef;
import org.jf.dexlib2.immutable.ImmutableDexFile;

public final class StringTables {
   private StringTables() {
   }

   static Set<String> decoderTables(DexContext original, NpModel model) {
      Set<String> tables = new HashSet<>();
      if (model.arrays().isEmpty()) {
         return Set.of();
      }

      for (Method method : original.methods().values()) {
         if (method.getImplementation() != null) {
            Set<String> readTables = new HashSet<>();

            for (Instruction instruction : method.getImplementation().getInstructions()) {
               if (instruction.getOpcode() == Opcode.SGET_OBJECT
                  && instruction instanceof ReferenceInstruction ref
                  && ref.getReference() instanceof FieldReference field
                  && model.arrays().containsKey(Signatures.of(field))) {
                  readTables.add(Signatures.of(field));
               }

               if (!model.arrayGetters().isEmpty()
                  && (instruction.getOpcode() == Opcode.INVOKE_STATIC || instruction.getOpcode() == Opcode.INVOKE_STATIC_RANGE)
                  && instruction instanceof ReferenceInstruction ref
                  && ref.getReference() instanceof MethodReference call) {
                  String field = model.arrayGetters().get(Signatures.of(call));
                  if (field != null && model.arrays().containsKey(field)) {
                     readTables.add(field);
                  }
               }
            }

            readTables.removeAll(tables);
            if (!readTables.isEmpty()) {
               CodeGraph graph = new CodeGraph(method.getImplementation());

               for (String field : readTables) {
                  if (reachesDecoder(graph, field, model)) {
                     tables.add(field);
                  }
               }
            }
         }
      }

      return Set.copyOf(tables);
   }

   private static boolean reachesDecoder(CodeGraph graph, String field, NpModel model) {
      BitSet[] before = new BitSet[graph.size()];
      before[0] = new BitSet();
      ArrayDeque<Integer> work = new ArrayDeque<>();
      work.add(0);
      long budget = Math.max(10000L, graph.size() * 256L);

      while (!work.isEmpty()) {
         if (--budget == 0L) {
            return false;
         }

         int i = work.removeFirst();
         Instruction instruction = graph.at(i);
         Opcode op = instruction.getOpcode();
         BitSet in = before[i];
         BitSet out = (BitSet)in.clone();
         if ((op == Opcode.INVOKE_STATIC || op == Opcode.INVOKE_STATIC_RANGE)
            && instruction instanceof ReferenceInstruction ref
            && ref.getReference() instanceof MethodReference call
            && model.helpers().decoders().contains(Signatures.of(call))) {
            int[] args = ConstantEvaluator.arguments(instruction);
            if (args.length == 4 && in.get(args[0])) {
               return true;
            }
         }

         out.andNot(RegisterLiveness.writes(instruction));
         if ((op == Opcode.MOVE_OBJECT || op == Opcode.MOVE_OBJECT_FROM16 || op == Opcode.MOVE_OBJECT_16)
            && in.get(((TwoRegisterInstruction)instruction).getRegisterB())) {
            out.set(NpHelpers.reg(instruction));
         }

         if (op == Opcode.SGET_OBJECT
            && instruction instanceof ReferenceInstruction ref
            && ref.getReference() instanceof FieldReference f
            && field.equals(Signatures.of(f))) {
            out.set(NpHelpers.reg(instruction));
         }

         if (op == Opcode.MOVE_RESULT_OBJECT && i > 0 && NpArrays.getter(graph.at(i - 1), field, model.arrayGetters())) {
            out.set(NpHelpers.reg(instruction));
         }

         for (int target : graph.successors(i)) {
            merge(before, target, out, work);
         }

         BitSet exceptional = (BitSet)in.clone();
         exceptional.or(out);

         for (int target : graph.handlers(i)) {
            merge(before, target, exceptional, work);
         }
      }

      return false;
   }

   private static void merge(BitSet[] before, int target, BitSet state, ArrayDeque<Integer> work) {
      if (before[target] == null) {
         before[target] = (BitSet)state.clone();
         work.add(target);
      } else {
         BitSet merged = (BitSet)before[target].clone();
         merged.or(state);
         if (!merged.equals(before[target])) {
            before[target] = merged;
            work.add(target);
         }
      }
   }

   public static DexFinalizer.Result remove(DexContext original, DexFile output, NpModel model) {
      Set<String> candidates = new HashSet<>(decoderTables(original, model));
      if (candidates.isEmpty()) {
         return new DexFinalizer.Result(output, PassResult.unchanged());
      }

      DexContext current = new DexContext(output);
      candidates.retainAll(NpArrays.discover(current, model.helpers()).keySet());
      Map<String, String> initializers = new HashMap<>();
      Map<String, Initializer> prefixes = new HashMap<>();

      for (String field : candidates) {
         String owner = current.fields().get(field).getDefiningClass();
         String initializer = owner + "-><clinit>()V";
         Method method = current.methods().get(initializer);
         if (method != null && method.getAnnotations().isEmpty() && current.fields().get(field).getAnnotations().isEmpty()) {
            initializers.put(field, initializer);
            prefixes.put(field, Initializer.find(new CodeGraph(method.getImplementation())));
         }
      }

      List<FieldReference> uses = FieldReferences.collect(current, Set.copyOf(initializers.values()));
      Set<String> removeFields = new TreeSet<>();
      Set<String> removeMethods = new HashSet<>();
      Map<String, Method> rewrittenInitializers = new HashMap<>();
      for (Map.Entry<String, String> entry : initializers.entrySet()) {

         Field field = current.fields().get(entry.getKey());
         if (!uses.stream().anyMatch(use -> FieldReferences.mayResolveTo(current, use, field))) {
            Initializer prefix = prefixes.get(entry.getKey());
            if (prefix != null) {
               if (prefix.pure()) {
                  removeMethods.add(entry.getValue());
                  removeFields.add(entry.getKey());
                  continue;
               }

               Method method = current.methods().get(entry.getValue());
               MethodContext context = new MethodContext(current, method);
               CodeGraph graph = context.graph();
               RegisterLiveness live = new RegisterLiveness(graph);
               BitSet writes = new BitSet();
               boolean safe = true;

               for (int i = 0; i < graph.size(); i++) {
                  if (prefix.prefix().get(i)) {
                     writes.or(RegisterLiveness.writes(graph.at(i)));
                  } else if (graph.at(i) instanceof ReferenceInstruction ref
                     && ref.getReference() instanceof FieldReference f
                     && FieldReferences.mayResolveTo(current, f, field)) {
                     safe = false;
                  }
               }

               for (int r = writes.nextSetBit(0); r >= 0; r = writes.nextSetBit(r + 1)) {
                  if (live.liveAfter(prefix.store(), r)) {
                     safe = false;
                  }
               }

               if (safe) {
                  ExceptionEdits.remove(context, prefix.prefix());
                  rewrittenInitializers.put(entry.getValue(), context.finish());
                  removeFields.add(entry.getKey());
               }
            }
         }
      }
      if (removeFields.isEmpty()) {
         return new DexFinalizer.Result(output, PassResult.unchanged());
      }

      List<ClassDef> classes = new ArrayList<>();

      for (ClassDef cls : current.classes().values()) {
         List<Field> fields = new ArrayList<>();
         List<Method> methods = new ArrayList<>();

         for (Field field : cls.getFields()) {
            if (!removeFields.contains(Signatures.of(field))) {
               fields.add(field);
            }
         }

         for (Method method : cls.getMethods()) {
            if (!removeMethods.contains(Signatures.of(method))) {
               methods.add(rewrittenInitializers.getOrDefault(Signatures.of(method), method));
            }
         }

         classes.add(
            new ImmutableClassDef(
               cls.getType(),
               cls.getAccessFlags(),
               cls.getSuperclass(),
               cls.getInterfaces(),
               cls.getSourceFile(),
               cls.getAnnotations(),
               fields,
               methods
            )
         );
      }

      List<String> notes = new ArrayList<>();
      notes.add("unused NP short array fields removed: " + removeFields.size());
      notes.add("pure NP table initializers removed: " + removeMethods.size());
      if (!rewrittenInitializers.isEmpty()) {
         notes.add("NP table prefixes removed; business initialization retained: " + rewrittenInitializers.size());
      }

      removeFields.forEach(field -> notes.add("removed NP string table: " + field));
      return new DexFinalizer.Result(
         new ImmutableDexFile(output.getOpcodes(), classes),
         new PassResult(removeFields.size() + removeMethods.size() + rewrittenInitializers.size(), notes)
      );
   }
}
