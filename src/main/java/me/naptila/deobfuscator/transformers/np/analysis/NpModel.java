package me.naptila.deobfuscator.transformers.np.analysis;

import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.ConstantAnalysis;
import me.naptila.deobfuscator.dex.ConstantEvaluator;
import me.naptila.deobfuscator.dex.Constants;
import me.naptila.deobfuscator.dex.Signatures;
import java.util.List;
import java.util.Map;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.TypeReference;

/** Offline facts shared by NP passes. Public views are read-only; proving a value does not prove a call removable. */
public final class NpModel {
   final NpHelpers helpers;

   public NpHelpers helpers() { return helpers; }
   public Map<String, Integer> fields() { return fields; }
   public Map<String, List<Short>> arrays() { return arrays; }
   public Map<String, String> arrayGetters() { return arrayGetters; }
   public Map<String, String> stringGetters() { return stringGetters; }
   public Map<String, Method> stringProxies() { return stringProxies; }

   final Map<String, Integer> fields;
   final Map<String, List<Short>> arrays;
   final Map<String, String> arrayGetters;
   final Map<String, String> stringGetters;
   final Map<String, Method> stringProxies;

   NpModel(NpHelpers helpers, Map<String, Integer> fields, Map<String, List<Short>> arrays) {
      this(helpers, fields, arrays, Map.of());
   }

   NpModel(NpHelpers helpers, Map<String, Integer> fields, Map<String, List<Short>> arrays, Map<String, String> arrayGetters) {
      this(helpers, fields, arrays, arrayGetters, Map.of());
   }

   NpModel(NpHelpers helpers, Map<String, Integer> fields, Map<String, List<Short>> arrays,
         Map<String, String> arrayGetters, Map<String, String> stringGetters) {
      this(helpers, fields, arrays, arrayGetters, stringGetters, Map.of());
   }

   NpModel(NpHelpers helpers, Map<String, Integer> fields, Map<String, List<Short>> arrays,
         Map<String, String> arrayGetters, Map<String, String> stringGetters, Map<String, Method> stringProxies) {
      this.helpers = helpers;
      this.fields = Map.copyOf(fields);
      this.arrays = Map.copyOf(arrays);
      this.arrayGetters = Map.copyOf(arrayGetters);
      this.stringGetters = Map.copyOf(stringGetters);
      this.stringProxies = Map.copyOf(stringProxies);
   }

   public void step(Instruction instruction, Constants state) {
      Object result = null;
      Opcode op = instruction.getOpcode();
      Object castTable = null;
      if (op == Opcode.CHECK_CAST
            && instruction instanceof ReferenceInstruction r && r.getReference() instanceof TypeReference type
            && type.getType().equals("[S")
            && state.get(NpHelpers.reg(instruction)) instanceof Constants.FieldValue field
            && this.arrays.containsKey(field.signature())) {
         castTable = field;
      }
      if ((op == Opcode.INVOKE_STATIC || op == Opcode.INVOKE_STATIC_RANGE)
         && instruction instanceof ReferenceInstruction r
         && r.getReference() instanceof MethodReference m) {
         String sig = Signatures.of(m);
         int[] args = ConstantEvaluator.arguments(instruction);
         if (this.helpers.hashes.contains(sig) && args.length == 1 && state.get(args[0]) instanceof String s) {
            result = s.hashCode();
         }

         NpHelpers.Guard guard = this.helpers.guards.get(sig);
         if (guard != null && args.length == 0 && this.fields.containsKey(guard.field())) {
            result = this.fields.get(guard.field()) ^ guard.key();
         }

         String table = this.arrayGetters.get(sig);
         if (args.length == 0 && table != null && this.arrays.containsKey(table)) {
            result = new Constants.FieldValue(table);
         }
         if (args.length == 0 && this.stringGetters.containsKey(sig)) {
            result = this.stringGetters.get(sig);
         }
      }

      ConstantEvaluator.step(instruction, state);
      if (castTable != null) {
         state.put(NpHelpers.reg(instruction), castTable);
      }
      if (result != null) {
         state.result(result);
      }

      if (instruction instanceof ReferenceInstruction r && r.getReference() instanceof FieldReference field) {
         String sig = Signatures.of(field);
         if (op == Opcode.SGET && this.fields.containsKey(sig)) {
            state.put(NpHelpers.reg(instruction), this.fields.get(sig));
         }

         // The verified initializer publishes this array without changing the source
         // register. Its subsequent local aliases have the same known contents.
         if ((op == Opcode.SGET_OBJECT || op == Opcode.SPUT_OBJECT) && this.arrays.containsKey(sig)) {
            state.put(NpHelpers.reg(instruction), new Constants.FieldValue(sig));
         }
      }
   }

   public ConstantAnalysis analyze(CodeGraph graph) {
      return new ConstantAnalysis(graph, this::step, true, true);
   }

   public boolean relevant(CodeGraph graph) {
      for (int i = 0; i < graph.size(); i++) {
         if (graph.at(i) instanceof ReferenceInstruction r) {
            if (r.getReference() instanceof MethodReference m
               && (
                  this.helpers.owners.contains(m.getDefiningClass())
                     || this.helpers.hashes.contains(Signatures.of(m))
                     || this.helpers.guards.containsKey(Signatures.of(m))
                     || this.helpers.decoders.contains(Signatures.of(m))
                     || this.arrayGetters.containsKey(Signatures.of(m))
                     || this.stringGetters.containsKey(Signatures.of(m))
                     || this.stringProxies.containsKey(Signatures.of(m))
               )) {
               return true;
            }

            if (r.getReference() instanceof FieldReference f && (this.fields.containsKey(Signatures.of(f)) || this.arrays.containsKey(Signatures.of(f)))) {
               return true;
            }
         }
      }

      return false;
   }
}
