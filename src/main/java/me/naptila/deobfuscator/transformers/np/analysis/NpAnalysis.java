package me.naptila.deobfuscator.transformers.np.analysis;

import me.naptila.deobfuscator.transformers.np.methodhiding.NpArrayGetters;

import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.ConstantAnalysis;
import me.naptila.deobfuscator.dex.Constants;
import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.Signatures;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jf.dexlib2.AccessFlags;
import org.jf.dexlib2.iface.Field;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.value.IntEncodedValue;

public final class NpAnalysis {
   final NpModel model;

   public NpModel model() { return model; }
   private final int rejectedFields;

   private NpAnalysis(DexContext dex) {
      NpHelpers helpers = new NpHelpers(dex);
      NpAnalysis.Fields verified = verifyFields(dex, helpers);

      for (int round = 0; round < 3 && NpHelperNormalization.expand(dex, new NpModel(helpers, verified.values(), Map.of())); round++) {
         verified = verifyFields(dex, helpers);
      }

      this.rejectedFields = verified.rejected();
      this.model = withStringGetters(dex, new NpModel(helpers, verified.values(), NpArrays.discover(dex, helpers)));
   }

   private static NpAnalysis.Fields verifyFields(DexContext dex, NpHelpers helpers) {
      Set<String> guardFields = new HashSet<>();
      helpers.guards.values().forEach(g -> guardFields.add(g.field()));
      Set<String> helperOwners = new HashSet<>(helpers.owners);
      // Normalization can prove additional helper methods after the initial owner
      // index was built. Their numeric fields still need the same write checks.
      for (String decoder : helpers.decoders) {
         String owner = decoder.substring(0, decoder.indexOf("->"));
         String prefix = owner + "->";
         if (helpers.hashes.stream().anyMatch(s -> s.startsWith(prefix))
               && helpers.guards.keySet().stream().anyMatch(s -> s.startsWith(prefix))) helperOwners.add(owner);
      }
      Map<String, Integer> candidates = new HashMap<>();

      for (Field field : dex.fields().values()) {
         if ((helperOwners.contains(field.getDefiningClass()) || guardFields.contains(Signatures.of(field)))
            && field.getType().equals("I")
            && AccessFlags.STATIC.isSet(field.getAccessFlags())
            && !AccessFlags.VOLATILE.isSet(field.getAccessFlags())
            && (field.getInitialValue() == null || field.getInitialValue() instanceof IntEncodedValue)) {
            // Omitted static int values are DEX's default zero. They still need
            // the same reachable-write validation as explicitly encoded values.
            int initial = field.getInitialValue() instanceof IntEncodedValue value ? value.getValue() : 0;
            candidates.put(Signatures.of(field), initial);
         }
      }

      int initial = candidates.size();

      boolean changed;
      do {
         Set<String> rejected = new HashSet<>();
         NpModel trial = new NpModel(helpers, candidates, Map.of());

         for (Method method : dex.methods().values()) {
            if (method.getImplementation() != null) {
               List<Instruction> writes = new ArrayList<>();

               for (Instruction i : method.getImplementation().getInstructions()) {
                  if (writtenField(i) != null && candidates.containsKey(writtenField(i))) {
                     writes.add(i);
                  }
               }

               if (!writes.isEmpty()) {
                  try {
                     CodeGraph graph = new CodeGraph(method.getImplementation());
                     ConstantAnalysis facts = trial.analyze(graph);

                     for (int i = 0; i < graph.size(); i++) {
                        String field = writtenField(graph.at(i));
                        if (field != null && candidates.containsKey(field)) {
                           Constants before = facts.before(i);
                           if (before != null && !Objects.equals(before.get(NpHelpers.reg(graph.at(i))), candidates.get(field))) {
                              rejected.add(field);
                           }
                        }
                     }
                  } catch (RuntimeException error) {
                     writes.forEach(ix -> rejected.add(writtenField(ix)));
                  }
               }
            }
         }

         changed = !rejected.isEmpty();
         rejected.forEach(candidates::remove);
      } while (changed);

      return new NpAnalysis.Fields(Map.copyOf(candidates), initial - candidates.size());
   }

   static String writtenField(Instruction i) {
      return i.getOpcode().name.startsWith("sput") && i instanceof ReferenceInstruction r && r.getReference() instanceof FieldReference f
         ? Signatures.of(f)
         : null;
   }

   public static NpAnalysis of(DexContext context) {
      return context.analysis(NpAnalysis.class, NpAnalysis::new);
   }

   public static NpModel model(DexContext context, boolean closedWorld) {
      return !closedWorld ? of(context).model : context.analysis(NpAnalysis.ClosedArrays.class, dex -> {
         NpModel base = of(dex).model;
         Map<String, String> getters = NpArrayGetters.discover(dex, base);
         Map<String, List<Short>> arrays = NpArrays.discover(dex, base.helpers, getters);
         return new NpAnalysis.ClosedArrays(withStringGetters(dex, new NpModel(base.helpers, base.fields, arrays, getters)));
      }).model();
   }

   public int stableIntegerFields() {
      return this.model.fields.size();
   }

   public static NpModel withAssumedTables(DexContext dex, NpModel base, Set<String> assumed) {
      if (assumed.isEmpty()) {
         return base;
      }

      HashMap<String, String> getters = new HashMap<>(base.arrayGetters);
      getters.putAll(NpArrayGetters.discover(dex, base, assumed));
      HashMap<String, List<Short>> arrays = new HashMap<>(base.arrays);
      arrays.putAll(NpArrays.discover(dex, base.helpers, getters, assumed));
      return withStringGetters(dex, new NpModel(base.helpers, base.fields, arrays, getters, base.stringGetters));
   }

   private static NpModel withStringGetters(DexContext dex, NpModel base) {
      var proxies = NpArrayGetters.stringProxies(dex, base);
      var trial = new NpModel(base.helpers, base.fields, base.arrays, base.arrayGetters, base.stringGetters, proxies);
      return new NpModel(base.helpers, base.fields, base.arrays, base.arrayGetters, NpArrayGetters.constantStrings(dex, trial), proxies);
   }

   public int rejectedIntegerFields() {
      return this.rejectedFields;
   }

   public int shortArrays() {
      return this.model.arrays.size();
   }

   public int hashHelpers() {
      return this.model.helpers.hashes.size();
   }

   public int stringHelpers() {
      return this.model.helpers.decoders.size();
   }

   private record ClosedArrays(NpModel model) {
   }

   private record Fields(Map<String, Integer> values, int rejected) {
   }
}
