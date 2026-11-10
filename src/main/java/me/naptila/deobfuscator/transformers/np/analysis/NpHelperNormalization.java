package me.naptila.deobfuscator.transformers.np.analysis;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.core.Pipeline;
import me.naptila.deobfuscator.dex.BranchThreading;
import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.ConstantAnalysis;
import me.naptila.deobfuscator.dex.ConstantEvaluator;
import me.naptila.deobfuscator.dex.Constants;
import me.naptila.deobfuscator.dex.DeadAssignments;
import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.DexPass;
import me.naptila.deobfuscator.dex.ExceptionEdits;
import me.naptila.deobfuscator.dex.MethodContext;
import me.naptila.deobfuscator.dex.RegisterLiveness;
import me.naptila.deobfuscator.dex.Signatures;
import me.naptila.deobfuscator.transformers.cleanup.UnreachableCodeTransformer;
import me.naptila.deobfuscator.transformers.np.NpCleanup;
import me.naptila.deobfuscator.transformers.np.controlflow.FlowerTransformer;
import me.naptila.deobfuscator.transformers.np.controlflow.OpaquePredicateTransformer;
import me.naptila.deobfuscator.transformers.np.instructions.InstructionTransformer;
import me.naptila.deobfuscator.transformers.np.methodhiding.MethodHidingTransformer;
import me.naptila.deobfuscator.transformers.np.numbers.NumberTransformer;
import me.naptila.deobfuscator.transformers.np.support.ProxyAccess;
import me.naptila.deobfuscator.transformers.np.strings.NpStringCalls;

import org.jf.dexlib2.AccessFlags;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Field;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.reference.MethodReference;

/** Runs bounded recovery on scratch methods, then rechecks semantic shapes. Never commits scratch edits or cleanup evidence. */
final class NpHelperNormalization {
   private NpHelperNormalization() {}
   static boolean expand(DexContext dex, final NpModel model) {
      List<Method> candidates = new ArrayList<>();

      for (ClassDef cls : dex.classes().values()) {
         Set<String> descriptors = new HashSet<>();

         for (Method m : cls.getMethods()) {
            descriptors.add(NpHelpers.descriptor(m));
         }

         if (descriptors.containsAll(Set.of("([SIII)Ljava/lang/String;", "(Ljava/lang/Object;)I", "()I"))) {
            for (Method m : cls.getMethods()) {
               String sig = Signatures.of(m);
               String desc = NpHelpers.descriptor(m);
               if (!model.helpers.hashes.contains(sig)
                  && !model.helpers.guards.containsKey(sig)
                  && !model.helpers.decoders.contains(sig)
                  && (desc.equals("()I") || desc.equals("(Ljava/lang/Object;)I") || desc.equals("([SIII)Ljava/lang/String;"))
                  && m.getImplementation() != null
                  && AccessFlags.STATIC.isSet(m.getAccessFlags())
                  && !AccessFlags.SYNCHRONIZED.isSet(m.getAccessFlags())
                  && !AccessFlags.DECLARED_SYNCHRONIZED.isSet(m.getAccessFlags())
                  && m.getImplementation().getTryBlocks().isEmpty()) {
                  int size = 0;

                  for (Instruction i : m.getImplementation().getInstructions()) {
                     size++;
                  }

                  if (size <= 192) {
                     candidates.add(m);
                  }
               }
            }
         }
      }

      if (candidates.isEmpty()) {
         return false;
      }

      MethodHidingTransformer proxies = new MethodHidingTransformer();
      proxies.prepareFacts(dex, model, false);
      OpaquePredicateTransformer predicates = new OpaquePredicateTransformer();
      predicates.prepareModel(model);
      FlowerTransformer flower = new FlowerTransformer();
      flower.prepareModel(model);
      InstructionTransformer instructions = new InstructionTransformer();
      instructions.prepareModel(model);
      DexPass temporaries = new DexPass() {
         @Override
         public String id() {
            return "np.helper-temporaries";
         }

         public PassResult run(MethodContext context) {
            return PassResult.changed(NpHelperNormalization.removeDeadHashes(context, model) + DeadAssignments.remove(context) + BranchThreading.run(context));
         }
      };
      Pipeline<MethodContext> pipeline = new Pipeline<>(List.of(proxies, predicates, flower, instructions, new UnreachableCodeTransformer(), temporaries), 8);
      NumberTransformer numbers = new NumberTransformer();
      numbers.prepareModel(model);
      NpCleanup cleanup = new NpCleanup();
      cleanup.prepareModel(model);
      Pipeline<MethodContext> decoderPipeline = new Pipeline<>(
         List.of(proxies, numbers, predicates, flower, instructions, new UnreachableCodeTransformer(), cleanup), 8
      );
      boolean changed = false;

      for (Method method : candidates) {
         try {
            MethodContext scratch = new MethodContext(dex, method);
            boolean decoder = NpHelpers.descriptor(method).equals("([SIII)Ljava/lang/String;");
            if ((decoder ? decoderPipeline : pipeline).run(scratch).converged()) {
               Method normalized = scratch.finish();
               String sig = Signatures.of(method);
               if (decoder) {
                  if (NpDecoderShape.matches(normalized)) {
                     changed |= model.helpers.decoders.add(sig);
                     // Every discarded operation was independently checked by the
                     // scratch pipeline. Also check the original owner's access
                     // and initialization before allowing removal at caller sites.
                     if (AccessFlags.PUBLIC.isSet(method.getAccessFlags())
                           && ProxyAccess.type(dex, method.getDefiningClass(), "")
                           && NpStringCalls.initializationSafe(dex, method.getDefiningClass(), ""))
                        model.helpers.removableDecoders.add(sig);
                  }
               } else {
                  if (NpHelpers.hash(normalized)) {
                     changed |= model.helpers.hashes.add(sig);
                     if (NpStringCalls.initializationSafe(dex, method.getDefiningClass(), "")) {
                        model.helpers.removableHashes.add(sig);
                     }
                  }

                  NpHelpers.Guard guard = NpHelpers.guard(normalized);
                  if (guard != null) {
                     Field field = dex.fields().get(guard.field());
                     if (field != null && ProxyAccess.member(dex, field, method.getDefiningClass(), false)) {
                        changed |= model.helpers.guards.putIfAbsent(sig, guard) == null;
                        if (NpStringCalls.initializationSafe(dex, method.getDefiningClass(), "")
                           && NpStringCalls.initializationSafe(dex, field.getDefiningClass(), "")) {
                           model.helpers.removableGuards.add(sig);
                        }
                     }
                  }
               }
            }
         } catch (RuntimeException unsupported) {
            // A failed scratch proof contributes no new facts; keep the original helper.
         }
      }

      return changed;
   }

   private static int removeDeadHashes(MethodContext context, NpModel model) {
      CodeGraph graph = context.graph();
      ConstantAnalysis facts = model.analyze(graph);
      RegisterLiveness live = new RegisterLiveness(graph);
      BitSet remove = new BitSet();

      for (int i = 0; i < graph.size(); i++) {
         Instruction instruction = graph.at(i);
         if ((instruction.getOpcode() == Opcode.INVOKE_STATIC || instruction.getOpcode() == Opcode.INVOKE_STATIC_RANGE)
            && instruction instanceof ReferenceInstruction r
            && r.getReference() instanceof MethodReference m
            && model.helpers.removableHashes.contains(Signatures.of(m))
            && ProxyAccess.member(context.dex(), m, context.original().getDefiningClass(), false)) {
            int[] args = ConstantEvaluator.arguments(instruction);
            Constants state = facts.before(i);
            if (args.length == 1 && state != null && state.get(args[0]) instanceof String) {
               if (i + 1 < graph.size() && graph.at(i + 1).getOpcode() == Opcode.MOVE_RESULT) {
                  if (graph.leaders().contains(i + 1) || !live.deadAfter(i + 1, graph.at(i + 1))) {
                     continue;
                  }

                  remove.set(i + 1);
               }

               remove.set(i);
            }
         }
      }

      if (!remove.isEmpty()) {
         ExceptionEdits.remove(context, remove);
      }

      return remove.cardinality();
   }
}
