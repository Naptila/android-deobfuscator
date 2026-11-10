package me.naptila.deobfuscator.transformers.np.methodhiding;

import me.naptila.deobfuscator.transformers.np.support.ProxyInstructions;

import me.naptila.deobfuscator.transformers.np.analysis.NpHelpers;
import me.naptila.deobfuscator.transformers.np.analysis.NpModel;
import me.naptila.deobfuscator.transformers.np.support.ProxyAccess;

import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.ConstantAnalysis;
import me.naptila.deobfuscator.dex.ConstantBranches;
import me.naptila.deobfuscator.dex.ConstantEvaluator;
import me.naptila.deobfuscator.dex.Constants;
import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.RegisterLiveness;
import me.naptila.deobfuscator.dex.Signatures;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jf.dexlib2.AccessFlags;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Field;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.immutable.ImmutableMethodImplementation;

final class HiddenProxies {
   final Map<String, HiddenProxies.Template> templates;
   final Set<String> unresolved;
   final Map<String, Integer> integerGuards;
   final Set<String> proxyClasses;

   HiddenProxies(DexContext dex, NpModel model) {
      this.proxyClasses = proxyClasses(dex, model);
      Map<String, HiddenProxies.Template> found = new HashMap<>();
      List<Method> pending = new ArrayList<>();

      for (Method method : dex.methods().values()) {
         HiddenProxies.Template template = recognize(dex, model, method);
         if (template == null) {
            template = GuardedProxyTrace.recognize(dex, model, method, Map.of(), classCandidate(model, method));
         }

         if (template != null) {
            found.put(Signatures.of(method), template);
         } else if (candidate(method, classCandidate(model, method))) {
            pending.add(method);
         }
      }

      // A guard may itself be hidden behind several verified proxies. Its value is
      // useful for path selection, but the original call still carries initialization.
      Map<String, Integer> integerGuards = new HashMap<>();
      for (int round = 0; round < 8; round++) {
         int previous = integerGuards.size();
         for (var entry : found.entrySet()) {
            if (integerGuards.containsKey(entry.getKey())) continue;
            Integer value = constantGuard(dex, model, entry.getValue(), integerGuards);
            if (value != null) integerGuards.put(entry.getKey(), value);
         }
         if (integerGuards.size() == previous) break;
         for (var it = pending.iterator(); it.hasNext();) {
            Method method = it.next();
            Template template = GuardedProxyTrace.recognize(dex, model, method, integerGuards, classCandidate(model, method));
            if (template != null) {
               found.put(Signatures.of(method), template);
               it.remove();
            }
         }
      }

      Set<String> cyclic = new HashSet<>();

      for (String key : found.keySet()) {
         cycle(key, key, found, new HashSet<>(), cyclic);
      }

      cyclic.forEach(found::remove);
      this.templates = Map.copyOf(found);
      Set<String> unproven = new HashSet<>();
      for (Method method : pending) {
         for (Instruction i : method.getImplementation().getInstructions()) {
            if (i instanceof ReferenceInstruction ref && ref.getReference() instanceof MethodReference call
                  && (model.helpers().guards().containsKey(Signatures.of(call)) || integerGuards.containsKey(Signatures.of(call)))) {
               unproven.add(Signatures.of(method));
               break;
            }
         }
      }
      this.unresolved = Set.copyOf(unproven);
      this.integerGuards = Map.copyOf(integerGuards);
   }

   private boolean classCandidate(NpModel model, Method method) {
      if (!proxyClasses.contains(method.getDefiningClass())) return false;
      String sig = Signatures.of(method);
      // Keep helper calls available to their own number, flow and string passes.
      return !model.helpers().hashes().contains(sig) && !model.helpers().guards().containsKey(sig)
         && !model.helpers().decoders().contains(sig);
   }

   /** Class identity selects candidates; every accepted method still needs its own complete trace. */
   private static Set<String> proxyClasses(DexContext dex, NpModel model) {
      Set<String> hashes = new HashSet<>(), decoders = new HashSet<>(), guards = new HashSet<>();
      for (String sig : model.helpers().hashes()) hashes.add(sig.substring(0, sig.indexOf("->")));
      for (String sig : model.helpers().decoders()) decoders.add(sig.substring(0, sig.indexOf("->")));
      for (var entry : model.helpers().guards().entrySet()) {
         String owner = entry.getKey().substring(0, entry.getKey().indexOf("->"));
         Field field = dex.fields().get(entry.getValue().field());
         // NP guards commonly read another proxy class's integer field.
         if (field != null && field.getType().equals("I") && AccessFlags.STATIC.isSet(field.getAccessFlags())) guards.add(owner);
      }
      hashes.retainAll(decoders);
      hashes.retainAll(guards);
      hashes.removeIf(owner -> {
         ClassDef cls = dex.classes().get(owner);
         if (cls == null || !AccessFlags.PUBLIC.isSet(cls.getAccessFlags())
               || !"Ljava/lang/Object;".equals(cls.getSuperclass()) || !cls.getInterfaces().isEmpty()) return true;
         int integers = 0, tables = 0;
         for (Field field : cls.getFields()) {
            int flags = field.getAccessFlags();
            if (!AccessFlags.STATIC.isSet(flags) || AccessFlags.VOLATILE.isSet(flags)) return true;
            if (field.getType().equals("I") && AccessFlags.PUBLIC.isSet(flags)) integers++;
            else if (field.getType().equals("[S") && AccessFlags.PRIVATE.isSet(flags) && AccessFlags.FINAL.isSet(flags)) tables++;
            else return true;
         }
         if (integers != 1 || tables > 1) return true;
         boolean stringHelper = false;
         for (Method method : cls.getMethods()) {
            if (method.getName().startsWith("<")) continue;
            if (!AccessFlags.PUBLIC.isSet(method.getAccessFlags()) || !AccessFlags.STATIC.isSet(method.getAccessFlags())) return true;
            stringHelper |= NpHelpers.descriptor(method).equals("(Ljava/lang/String;)Ljava/lang/String;");
         }
         return !stringHelper;
      });
      return Set.copyOf(hashes);
   }

   private static boolean candidate(Method method, boolean proxyClass) {
      int flags = method.getAccessFlags();
      if (method.getImplementation() == null || method.getName().startsWith("<")
            || !AccessFlags.PUBLIC.isSet(flags) || !AccessFlags.STATIC.isSet(flags)
            || AccessFlags.SYNCHRONIZED.isSet(flags) || AccessFlags.DECLARED_SYNCHRONIZED.isSet(flags)
            || !method.getImplementation().getTryBlocks().isEmpty()) return false;
      int size = 0;
      for (Instruction ignored : method.getImplementation().getInstructions()) if (++size > 512) return false;
      return size >= (proxyClass ? 2 : 5);
   }

   private static Integer constantGuard(DexContext dex, NpModel model, Template template, Map<String, Integer> aliases) {
      if (!template.method().getParameterTypes().isEmpty() || !template.method().getReturnType().equals("I")
            || template.returned().getOpcode() != Opcode.RETURN) return null;
      Constants state = new Constants();
      for (Instruction i : template.body()) {
         if (i instanceof ReferenceInstruction ref) {
            if ((i.getOpcode() == Opcode.INVOKE_STATIC || i.getOpcode() == Opcode.INVOKE_STATIC_RANGE)
                  && ref.getReference() instanceof MethodReference call && ConstantEvaluator.arguments(i).length == 0
                  && (model.helpers().guards().containsKey(Signatures.of(call)) || aliases.containsKey(Signatures.of(call)))
                  && ProxyAccess.member(dex, call, template.method().getDefiningClass(), false)) {
               model.step(i, state);
               Integer value = aliases.get(Signatures.of(call));
               if (value != null) state.result(value);
               if (!(state.result() instanceof Integer)) return null;
            } else if (i.getOpcode() == Opcode.SGET && ref.getReference() instanceof FieldReference field
                  && model.fields().containsKey(Signatures.of(field))
                  && ProxyAccess.member(dex, field, template.method().getDefiningClass(), false)) {
               model.step(i, state);
            } else return null; // No business calls, writes, casts or unverified reads.
         } else if (!ConstantEvaluator.step(i, state)) return null;
      }
      return state.get(NpHelpers.reg(template.returned())) instanceof Integer value ? value : null;
   }

   private static void cycle(String root, String current, Map<String, HiddenProxies.Template> templates, Set<String> path, Set<String> cyclic) {
      if (!path.add(current)) {
         cyclic.add(root);
      } else {
         HiddenProxies.Template t = templates.get(current);
         if (t != null) {
            for (Instruction i : t.body()) {
               if (i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m && templates.containsKey(Signatures.of(m))) {
                  cycle(root, Signatures.of(m), templates, path, cyclic);
               }
            }
         }

         path.remove(current);
      }
   }

   private static HiddenProxies.Template recognize(DexContext dex, NpModel model, Method method) {
      int flags = method.getAccessFlags();
      if (method.getImplementation() != null
         && !method.getName().startsWith("<")
         && AccessFlags.STATIC.isSet(flags)
         && AccessFlags.PUBLIC.isSet(flags)
         && !AccessFlags.SYNCHRONIZED.isSet(flags)
         && !AccessFlags.DECLARED_SYNCHRONIZED.isSet(flags)
         && method.getImplementation().getTryBlocks().isEmpty()) {
         CodeGraph g = new CodeGraph(method.getImplementation());
         if (g.size() >= 5
            && g.size() <= 32
            && g.at(0).getOpcode() == Opcode.INVOKE_STATIC
            && ConstantEvaluator.arguments(g.at(0)).length == 0
            && g.at(1).getOpcode() == Opcode.MOVE_RESULT
            && CodeGraph.isIf(g.at(2).getOpcode())) {
            MethodReference guard = (MethodReference)((ReferenceInstruction)g.at(0)).getReference();
            if (!model.helpers().removableGuards().contains(Signatures.of(guard))) {
               return null;
            }

            if (model.helpers().guards().containsKey(Signatures.of(guard)) && ProxyAccess.member(dex, guard, method.getDefiningClass(), false)) {
               Field guardField = dex.fields().get(model.helpers().guards().get(Signatures.of(guard)).field());
               if (guardField != null && ProxyAccess.member(dex, guardField, guard.getDefiningClass(), false)) {
                  ConstantAnalysis facts = model.analyze(g);
                  if (facts.before(2) == null) {
                     return null;
                  }

                  Boolean decision = ConstantBranches.decision(g.at(2), facts.before(2));
                  if (decision == null) {
                     return null;
                  }

                  int cursor = decision ? g.successors(2).get(0) : 3;
                  List<Instruction> body = new ArrayList<>();
                  Set<Integer> visited = new HashSet<>();
                  int actions = 0;

                  while (visited.add(cursor)) {
                     Instruction i = g.at(cursor);
                     Opcode op = i.getOpcode();
                     String name = op.name;
                     if (name.startsWith("return")) {
                        if (!body.isEmpty() && actions <= 1) {
                           int words = method.getParameterTypes().stream().mapToInt(t -> ProxyInstructions.wide(t.toString()) ? 2 : 1).sum();

                           for (Instruction step : body) {
                              for (int reg : NpHelpers.registers(step)) {
                                 if (reg < 0 || reg >= g.registers()) {
                                    return null;
                                 }
                              }
                           }

                           List<Instruction> straight = new ArrayList<>(body);
                           straight.add(i);
                           CodeGraph trace = new CodeGraph(new ImmutableMethodImplementation(g.registers(), straight, List.of(), List.of()));
                           RegisterLiveness live = new RegisterLiveness(trace);

                           for (int r = 0; r < g.registers() - words; r++) {
                              if (live.liveBefore(0, r)) {
                                 return null;
                              }
                           }

                           return new HiddenProxies.Template(method, List.copyOf(body), i, guard, false, g.registers(), false);
                        }

                        return null;
                     }

                     if (!CodeGraph.isGoto(op)) {
                        boolean invoke = name.startsWith("invoke-static")
                           || name.startsWith("invoke-virtual")
                           || name.startsWith("invoke-interface")
                           || name.startsWith("invoke-direct");
                        boolean field = name.startsWith("iget") || name.startsWith("sget") || name.startsWith("iput") || name.startsWith("sput");
                        if (invoke) {
                           MethodReference target = (MethodReference)((ReferenceInstruction)i).getReference();
                           if (target.getName().startsWith("<")) {
                              return null;
                           }

                           actions++;
                        } else if (field) {
                           actions++;
                        } else if (!name.startsWith("const") && !name.startsWith("move") && op != Opcode.CHECK_CAST && op != Opcode.NOP) {
                           return null;
                        }

                        if (op == Opcode.MOVE_EXCEPTION || op == Opcode.CONST_METHOD_HANDLE || op == Opcode.CONST_METHOD_TYPE) {
                           return null;
                        }

                        body.add(i);
                        if (g.successors(cursor).size() != 1) {
                           return null;
                        }

                        cursor = g.successors(cursor).get(0);
                     } else {
                        cursor = g.successors(cursor).get(0);
                     }
                  }

                  return null;
               } else {
                  return null;
               }
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


   record Template(Method method, List<Instruction> body, Instruction returned, MethodReference guard, boolean traced, int registers, boolean classProxy) {
   }
}
