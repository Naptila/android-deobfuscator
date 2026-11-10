package me.naptila.deobfuscator.transformers.np.methodhiding;

import me.naptila.deobfuscator.transformers.np.analysis.NpHelpers;
import me.naptila.deobfuscator.transformers.np.analysis.NpModel;
import me.naptila.deobfuscator.transformers.np.strings.NpStringCalls;

import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.ConstantEvaluator;
import me.naptila.deobfuscator.dex.Constants;
import me.naptila.deobfuscator.dex.DynamicMethodAccess;
import me.naptila.deobfuscator.dex.FieldReferences;
import me.naptila.deobfuscator.dex.MethodReferences;
import me.naptila.deobfuscator.dex.Signatures;
import java.util.BitSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.Field;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.instruction.TwoRegisterInstruction;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.immutable.ImmutableMethod;
import org.jf.dexlib2.immutable.ImmutableMethodImplementation;

public final class NpArrayGetters {
   /** Branch-free value traces; their original calls still carry all effects and exceptions. */
   public static Map<String, Method> stringProxies(DexContext dex, NpModel model) {
      if (model.arrays().isEmpty()) return Map.of();
      var proxies = new HiddenProxies(dex, model);
      Map<String, Method> result = new HashMap<>();
      for (Method method : dex.methods().values()) {
         if (!method.getReturnType().equals("Ljava/lang/String;")
               || method.getParameterTypes().stream().anyMatch(t -> t.toString().equals("J") || t.toString().equals("D"))) continue;
         String sig = Signatures.of(method);
         var trace = proxies.templates.get(sig);
         if (trace == null) trace = GuardedProxyTrace.valueTrace(dex, model, method, proxies.integerGuards);
         if (trace != null && trace.returned().getOpcode() == Opcode.RETURN_OBJECT) {
            var instructions = new ArrayList<>(trace.body());
            instructions.add(trace.returned());
            result.put(sig, new ImmutableMethod(method.getDefiningClass(), method.getName(), method.getParameters(),
                  method.getReturnType(), method.getAccessFlags(), method.getAnnotations(), method.getHiddenApiRestrictions(),
                  new ImmutableMethodImplementation(trace.registers(), instructions, List.of(), List.of())));
         }
      }
      return Map.copyOf(result);
   }

   /** Constant return values of verified traces; this supplies no call-deletion proof. */
   public static Map<String, String> constantStrings(DexContext dex, NpModel model) {
      if (model.arrays().isEmpty()) return model.stringGetters();
      Map<String, String> result = new HashMap<>(model.stringGetters());
      for (int round = 0; round < 8; round++) {
         int previous = result.size();
         for (var entry : model.stringProxies().entrySet()) {
            Method method = entry.getValue();
            if (result.containsKey(entry.getKey()) || !method.getParameterTypes().isEmpty()) continue;
            Constants state = new Constants();
            for (Instruction i : method.getImplementation().getInstructions()) {
               if (i.getOpcode() == Opcode.RETURN_OBJECT) {
                  if (state.get(NpHelpers.reg(i)) instanceof String value) result.put(entry.getKey(), value);
                  break;
               }
               String value = NpStringCalls.value(model, i, state);
               String nested = null;
               if ((i.getOpcode() == Opcode.INVOKE_STATIC || i.getOpcode() == Opcode.INVOKE_STATIC_RANGE)
                     && i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m
                     && ConstantEvaluator.arguments(i).length == 0) nested = result.get(Signatures.of(m));
               model.step(i, state);
               if (value != null) state.result(value);
               else if (nested != null) state.result(nested);
            }
         }
         if (result.size() == previous) break;
      }
      return Map.copyOf(result);
   }

   public static Map<String, String> discover(DexContext dex, NpModel model) {
      return discover(dex, model, Set.of());
   }

   public static Map<String, String> discover(DexContext dex, NpModel model, Set<String> assumed) {
      MethodReferences references = new MethodReferences(dex);
      if (assumed.isEmpty() && !DynamicMethodAccess.hazards(dex, references).isEmpty()) {
         return Map.of();
      }

      if (assumed.isEmpty()) {
         for (MethodReferences.Use use : references.uses()) {
            String owner = use.method().getDefiningClass();
            String name = use.method().getName();
            if (owner.startsWith("Ljava/lang/reflect/")
               || owner.startsWith("Ljava/lang/invoke/")
               || owner.contains("/Unsafe;")
               || owner.equals("Ljava/lang/Class;") && (name.startsWith("getField") || name.startsWith("getDeclaredField"))) {
               return Map.of();
            }
         }
      }

      if (assumed.isEmpty()) {
         for (Method method : dex.methods().values()) {
            if (method.getImplementation() != null) {
               for (Instruction insn : method.getImplementation().getInstructions()) {
                  if (insn.getOpcode() == Opcode.CONST_METHOD_HANDLE
                     || insn.getOpcode().name.startsWith("invoke-custom")
                     || insn.getOpcode().name.startsWith("invoke-polymorphic")) {
                     return Map.of();
                  }
               }
            }
         }
      }

      Map<String, String> result = new HashMap<>();
      List<FieldReference> metadataFields = FieldReferences.collect(dex, dex.methods().keySet());
      List<FieldReference> allFields = FieldReferences.collect(dex, Set.of());

      for (Map.Entry<String, HiddenProxies.Template> entry : (new HiddenProxies(dex, model)).templates.entrySet()) {
         HiddenProxies.Template t = entry.getValue();
         Method method = t.method();
         if (method.getParameterTypes().isEmpty()
            && method.getReturnType().equals("[S")
            && method.getAnnotations().isEmpty()
            && !dex.classes()
               .get(method.getDefiningClass())
               .getAnnotations()
               .stream()
               .anyMatch(
                  a -> a.getVisibility() != 2
                     || !Set.of(
                           "Ldalvik/annotation/InnerClass;",
                           "Ldalvik/annotation/EnclosingClass;",
                           "Ldalvik/annotation/EnclosingMethod;",
                           "Ldalvik/annotation/MemberClasses;",
                           "Ldalvik/annotation/Signature;"
                        )
                        .contains(a.getType())
               )) {
            String field = null;
            BitSet values = new BitSet();
            boolean valid = true;

            for (Instruction insn : t.body()) {
               if (insn.getOpcode() == Opcode.SGET_OBJECT
                  && insn instanceof ReferenceInstruction r
                  && r.getReference() instanceof FieldReference f
                  && f.getType().equals("[S")
                  && field == null
                  && f.getDefiningClass().equals(method.getDefiningClass())) {
                  field = Signatures.of(f);
                  values.set(NpHelpers.reg(insn));
               } else if (!insn.getOpcode().name.startsWith("move-object") || !(insn instanceof TwoRegisterInstruction move)) {
                  if (assumed.isEmpty()
                     || !insn.getOpcode().name.startsWith("invoke-static")
                     || !(insn instanceof ReferenceInstruction r)
                     || !(r.getReference() instanceof MethodReference m)
                     || !model.helpers().guards().containsKey(Signatures.of(m))) {
                     valid = false;
                     break;
                  }
               } else {
                  values.set(move.getRegisterA(), values.get(move.getRegisterB()));
               }
            }

            if (valid
               && field != null
               && t.returned().getOpcode() == Opcode.RETURN_OBJECT
               && values.get(NpHelpers.reg(t.returned()))
               && (assumed.isEmpty() || assumed.contains(field))) {
               Field definition = dex.fields().get(field);
               if (definition != null
                  && !metadataFields.stream().anyMatch(fx -> FieldReferences.mayResolveTo(dex, fx, definition))
                  && !allFields.stream()
                     .anyMatch(fx -> !Signatures.of(fx).equals(Signatures.of(definition)) && FieldReferences.mayResolveTo(dex, fx, definition))) {
                  for (MethodReferences.Use use : references.uses()) {
                     if (MethodReferences.mayResolveTo(dex, use.method(), method) && (!use.directCall() || !Signatures.of(use.method()).equals(entry.getKey()))
                        )
                      {
                        valid = false;
                     }
                  }

                  if (valid) {
                     result.put(entry.getKey(), field);
                  }
               }
            }
         }
      }

      return Map.copyOf(result);
   }
}
