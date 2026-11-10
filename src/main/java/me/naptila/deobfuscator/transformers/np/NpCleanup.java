package me.naptila.deobfuscator.transformers.np;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.transform.TransformerProvider;
import me.naptila.deobfuscator.transformers.np.analysis.NpHelpers;
import me.naptila.deobfuscator.transformers.np.analysis.NpModel;
import me.naptila.deobfuscator.transformers.np.controlflow.ComparisonDispatchers;
import me.naptila.deobfuscator.transformers.np.controlflow.FlowerPatterns;
import me.naptila.deobfuscator.transformers.np.strings.NpStringCalls;
import me.naptila.deobfuscator.transformers.np.strings.StringTables;
import me.naptila.deobfuscator.transformers.np.support.ProxyAccess;

import org.jf.dexlib2.AccessFlags;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.instruction.TwoRegisterInstruction;
import org.jf.dexlib2.iface.instruction.OneRegisterInstruction;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.TypeReference;

public final class NpCleanup extends NpTransformer implements DexFinalizer {
   private final boolean removeProtectedStringCalls;

   public NpCleanup() {
      this(false);
   }

   public NpCleanup(boolean removeProtectedStringCalls) {
      this(removeProtectedStringCalls, false);
   }

   public NpCleanup(boolean removeProtectedStringCalls, boolean closedWorld) {
      this(removeProtectedStringCalls, closedWorld, Set.of());
   }

   public NpCleanup(boolean removeProtectedStringCalls, boolean closedWorld, Set<String> assumed) {
      super(closedWorld, assumed);
      this.removeProtectedStringCalls = removeProtectedStringCalls;
   }

   @Override
   public DexFinalizer.Phase phase() {
      return DexFinalizer.Phase.COLLECT_TABLES;
   }

   @Override
   public String id() {
      return "np.cleanup";
   }

   @Override
   public DexFinalizer.Result finish(DexContext original, DexFile rewritten) {
      return StringTables.remove(original, rewritten, this.model);
   }

   public PassResult run(MethodContext context) {
      CodeGraph original = context.originalGraph();
      if (!this.applies(context, original) && !this.model.stringGetters().containsKey(Signatures.of(context.original()))
            && FlowerPatterns.find(original, this.model).isEmpty() && ComparisonDispatchers.find(original).isEmpty()) {
         // Optimization can rearrange ordinary short-circuit and switch edges
         // without adding a helper reference to the affected business method.
         // These layout rules need no helper-derived value or deletion proof.
         if (this.model.helpers().owners().isEmpty()
               || this.model.helpers().owners().contains(context.original().getDefiningClass())) return PassResult.unchanged();
         int layouts = SwitchDefaults.run(context) + SwitchDefaultEdges.run(context);
         int regions = SharedConditionalRegions.run(context);
         if (layouts + regions != 0) layouts += BranchThreading.run(context);
         List<String> notes = new ArrayList<>();
         if (layouts != 0) notes.add("plain NP control-flow layouts normalized: " + layouts);
         if (regions != 0) notes.add("shared conditional regions specialized: " + regions);
         return new PassResult(layouts + regions, notes);
      }

      int total = this.foldIntegerMoves(context) + RedundantMoves.run(context);
      int decodedCalls = 0;
      int hashCalls = 0;
      int protectedCalls = 0;
      int protectedReads = 0;
      int initializedReads = 0;
      int harmlessReads = 0;
      boolean protectedStrings = this.removeProtectedStringCalls
            && (hasDecoder(original, this.model) || hasDecoder(context.graph(), this.model));

      while (true) {
         CodeGraph graph = context.graph();
         ConstantAnalysis facts = this.model.analyze(graph);
         RegisterLiveness live = new RegisterLiveness(graph);
         Map<String, BitSet> initialized = null;
         int initializationCalls = 0;
         BitSet remove = new BitSet();
         Set<Integer> payloads = new HashSet<>();

         for (int i = 0; i < graph.size(); i++) {
            if (CodeGraph.isSwitch(graph.at(i).getOpcode()) || graph.at(i).getOpcode() == Opcode.FILL_ARRAY_DATA) {
               payloads.add(graph.payloadIndex(i));
            }
         }

         for (int i = 0; i < graph.size(); i++) {
            Instruction instruction = graph.at(i);
            Opcode op = instruction.getOpcode();
            if (graph.isPayload(i)) {
               if (!payloads.contains(i)) {
                  remove.set(i);
               }
            } else if (op != Opcode.NOP) {
               Constants state = facts.before(i);
               boolean hasResult = i + 1 < graph.size() && isResult(graph.at(i + 1).getOpcode());
               boolean unused = !hasResult || !graph.leaders().contains(i + 1) && live.deadAfter(i + 1, graph.at(i + 1));
               MethodReference hash = knownHash(context, instruction, state);
               boolean pureHash = false;
               if (hash != null) {
                  pureHash = this.model.helpers().removableHashes().contains(Signatures.of(hash))
                        || hash.getDefiningClass().equals(context.original().getDefiningClass());
                  if (!pureHash) {
                     if (initialized == null) initialized = initializedBefore(context, graph);
                     BitSet sites = initialized.get(hash.getDefiningClass());
                     pureHash = sites != null && sites.get(i);
                  }
                  if (!pureHash && unused) initializationCalls++;
               }
               boolean protectedThrow = op.canThrow() && !graph.protection(i).isEmpty();
               boolean initializedRead = false;
               if (protectedThrow && op == Opcode.SGET && live.deadAfter(i, instruction)
                     && instruction instanceof ReferenceInstruction ref && ref.getReference() instanceof FieldReference field
                     && this.model.fields().containsKey(Signatures.of(field))) {
                  var definition = context.dex().fields().get(Signatures.of(field));
                  if (definition != null && AccessFlags.STATIC.isSet(definition.getAccessFlags())
                        && !AccessFlags.VOLATILE.isSet(definition.getAccessFlags())
                        && ProxyAccess.member(context.dex(), field, context.original().getDefiningClass(), false)) {
                     if (initialized == null) initialized = initializedBefore(context, graph);
                     BitSet sites = initialized.get(field.getDefiningClass());
                     initializedRead = sites != null && sites.get(i);
                  }
               }
               boolean harmlessRead = !initializedRead && protectedThrow && op == Opcode.SGET
                     && live.deadAfter(i, instruction) && this.stableRead(context, instruction);
               boolean unusedCast = op == Opcode.CHECK_CAST && instruction instanceof ReferenceInstruction ref
                     && ref.getReference() instanceof TypeReference type && state != null
                     && (type.getType().equals("[S")
                           && state.get(((OneRegisterInstruction) instruction).getRegisterA()) instanceof Constants.FieldValue field
                           && this.model.arrays().containsKey(field.signature())
                        || type.getType().equals("Ljava/lang/String;")
                           && state.get(((OneRegisterInstruction) instruction).getRegisterA()) instanceof String)
                     && !live.liveAfter(i, ((OneRegisterInstruction) instruction).getRegisterA());
               if (!protectedThrow || protectedStrings || pureHash || unusedCast || initializedRead || harmlessRead) {
                  boolean decoder = context.decodedStringCall(context.code().getInstructions().get(i)) || NpStringCalls.removable(this.model, instruction, state);
                  if (!protectedThrow || decoder || pureHash || unusedCast || initializedRead || harmlessRead || removableRead(context, instruction, this.model)) {
                     if (decoder || pureHash || this.pureGuardCall(context, instruction, state)) {
                        if (unused) {
                           remove.set(i);
                           if (pureHash) hashCalls++;
                           if (decoder) {
                              decodedCalls++;
                           }

                           if (decoder && protectedThrow) {
                              protectedCalls++;
                           }

                           if (hasResult) {
                              remove.set(i + 1);
                           }
                        }
                     } else if (unusedCast || initializedRead || harmlessRead || live.deadAfter(i, instruction) && (DeadAssignments.isPure(instruction) || this.stableRead(context, instruction))) {
                        remove.set(i);
                        if (initializedRead) initializedReads++;
                        else if (harmlessRead) harmlessReads++;
                        else if (protectedThrow) {
                           protectedReads++;
                        }
                     }
                  }
               }
            }
         }

         if (remove.isEmpty()) {
            total += BranchThreading.run(context);
            total += SwitchDefaults.run(context);
            total += SwitchDefaultEdges.run(context);
            int handlers = HandlerEntries.run(context);
            int regions = SharedConditionalRegions.run(context, true);
            int literals = HandlerLiteralRegisters.run(context);
            // Finish dispatcher/region cleanup before changing its copy layout.
            // Early motion can hide the shared regions that still need specialization.
            int copies = total + handlers + regions + literals == 0 ? ConditionalCopies.run(context) : 0;
            int constants = total + handlers + regions + literals + copies == 0 ? ConditionalCopies.runLiterals(context) : 0;
            int tails = total + handlers + regions + literals + copies + constants == 0 ? SpecializedTails.run(context) : 0;
            int layouts = total + handlers + regions + literals + copies + constants + tails == 0 ? BlockLayout.run(context) : 0;
            total += handlers + copies + regions + literals + constants + tails + layouts;
            List<String> notes = new ArrayList<>();
            if (decodedCalls != 0) {
               notes.add("unused proven NP string calls removed: " + decodedCalls);
            }
            if (hashCalls != 0) notes.add("unused proven NP hash calls removed: " + hashCalls);
            if (initializedReads != 0) notes.add("redundant initialized NP field reads removed: " + initializedReads);
            if (harmlessReads != 0) notes.add("unused harmless NP field reads removed: " + harmlessReads);
            if (initializationCalls != 0) notes.add("NP hash calls retained for class initialization: " + initializationCalls);

            if (protectedCalls + protectedReads != 0) {
               notes.add("protected NP string calls removed: " + protectedCalls);
               notes.add("protected NP string scaffold reads removed: " + protectedReads);
               notes.add("removeProtectedStringCalls enabled: allocation, linkage and VM failure behavior may differ");
            }

            if (handlers != 0) {
               notes.add("split exception entries reconnected: " + handlers);
            }

            if (regions != 0) {
               notes.add("shared conditional regions specialized: " + regions);
            }

            if (copies != 0) notes.add("copies delayed to live conditional edges: " + copies);
            if (constants != 0) notes.add("integer constants delayed to live conditional edges: " + constants);
            if (tails != 0) notes.add("constant terminal traces specialized: " + tails);
            if (layouts != 0) notes.add("NP method blocks reordered: " + layouts);

            if (literals != 0) {
               notes.add("string temporaries separated from handler registers: " + literals);
            }

            return new PassResult(total, notes);
         }

         ExceptionEdits.remove(context, remove);
         total += remove.cardinality();
      }
   }

   private static boolean isResult(Opcode op) {
      return op == Opcode.MOVE_RESULT || op == Opcode.MOVE_RESULT_OBJECT || op == Opcode.MOVE_RESULT_WIDE;
   }

   private int foldIntegerMoves(MethodContext context) {
      CodeGraph graph = context.graph();
      ConstantAnalysis facts = this.model.analyze(graph);
      List<Edits.Edit> edits = new ArrayList<>();

      for (int i = 0; i < graph.size(); i++) {
         Instruction instruction = graph.at(i);
         Opcode op = instruction.getOpcode();
         if (op == Opcode.MOVE || op == Opcode.MOVE_FROM16 || op == Opcode.MOVE_16) {
            TwoRegisterInstruction move = (TwoRegisterInstruction)instruction;
            Constants state = facts.before(i);
            if (move.getRegisterA() <= 255 && state != null && state.get(move.getRegisterB()) instanceof Integer value) {
               edits.add(new Edits.Edit(i, false, List.of(Edits.constant(move.getRegisterA(), value))));
            }
         }
      }

      Edits.apply(context.code(), edits);
      return edits.size();
   }

   private MethodReference knownHash(MethodContext context, Instruction i, Constants state) {
      if (state == null || (i.getOpcode() != Opcode.INVOKE_STATIC && i.getOpcode() != Opcode.INVOKE_STATIC_RANGE)
            || !(i instanceof ReferenceInstruction ref) || !(ref.getReference() instanceof MethodReference method)
            || !this.model.helpers().hashes().contains(Signatures.of(method))
            || !ProxyAccess.member(context.dex(), method, context.original().getDefiningClass(), false)) return null;
      int[] args = ConstantEvaluator.arguments(i);
      return args.length == 1 && state.get(args[0]) instanceof String ? method : null;
   }

   private Map<String, BitSet> initializedBefore(MethodContext context, CodeGraph graph) {
      Set<String> owners = new HashSet<>();
      for (int i = 0; i < graph.size(); i++) {
         if (graph.at(i) instanceof ReferenceInstruction ref && ref.getReference() instanceof MethodReference method
               && this.model.helpers().hashes().contains(Signatures.of(method))) owners.add(method.getDefiningClass());
         if (graph.at(i) instanceof ReferenceInstruction ref && ref.getReference() instanceof FieldReference field
               && this.model.fields().containsKey(Signatures.of(field))) owners.add(field.getDefiningClass());
      }
      return ProxyAccess.initializedBefore(context, graph, owners);
   }

   private boolean pureGuardCall(MethodContext context, Instruction i, Constants state) {
      if (!(
         state != null
            && (i.getOpcode() == Opcode.INVOKE_STATIC || i.getOpcode() == Opcode.INVOKE_STATIC_RANGE)
            && i instanceof ReferenceInstruction r
            && r.getReference() instanceof MethodReference m
      )) {
         return false;
      } else {
         if (!ProxyAccess.member(context.dex(), m, context.original().getDefiningClass(), false)) {
            return false;
         }

         String signature = Signatures.of(m);
         NpHelpers.Guard guard = this.model.helpers().guards().get(signature);
         if (guard != null) {
            return this.model.helpers().removableGuards().contains(signature) && this.model.fields().containsKey(guard.field());
         }

         return false;
      }
   }

   private boolean stableRead(MethodContext context, Instruction i) {
      if (!(i instanceof ReferenceInstruction r && r.getReference() instanceof FieldReference f)) {
         return false;
      } else {
         return i.getOpcode() == Opcode.SGET
            ? this.model.fields().containsKey(Signatures.of(f))
               && ProxyAccess.member(context.dex(), f, context.original().getDefiningClass(), false)
               && NpStringCalls.initializationSafe(context.dex(), f.getDefiningClass(), context.original().getDefiningClass())
            : i.getOpcode() == Opcode.SGET_OBJECT
               && this.model.arrays().containsKey(Signatures.of(f))
               && f.getDefiningClass().equals(context.original().getDefiningClass());
      }
   }
    static boolean hasDecoder(CodeGraph graph, NpModel model) {
        for (int i = 0; i < graph.size(); i++) if (NpStringCalls.isDecoder(model, graph.at(i))) return true;
        return false;
    }
    static boolean removableRead(MethodContext context, Instruction instruction, NpModel model) {
        if (!(instruction instanceof ReferenceInstruction ref) || !(ref.getReference() instanceof FieldReference field)) return false;
        String signature = Signatures.of(field);
        if (instruction.getOpcode() == Opcode.SGET_OBJECT)
            return model.arrays().containsKey(signature) && field.getDefiningClass().equals(context.original().getDefiningClass())
                    && !context.original().getName().equals("<clinit>");
        if (instruction.getOpcode() != Opcode.SGET || !model.fields().containsKey(signature)) return false;
        var definition = context.dex().findField(signature).orElse(null);
        var owner = context.dex().classes().get(field.getDefiningClass());
        // Helper recognition already excludes custom initializers and non-Object superclasses.
        return definition != null && owner != null && model.helpers().owners().contains(owner.getType())
                && AccessFlags.PUBLIC.isSet(owner.getAccessFlags()) && AccessFlags.PUBLIC.isSet(definition.getAccessFlags())
                && AccessFlags.STATIC.isSet(definition.getAccessFlags());
    }

    /** Compatibility entry for existing YAML configurations. */
    public static final class Provider implements TransformerProvider {
        public String id() { return "np.cleanup"; }
        public String description() { return "Legacy explicit NP cleanup; NP features schedule this automatically"; }
        public boolean internal() { return true; }
        public DexPass create(TransformerOptions options) {
            options.requireOnly("removeProtectedStringCalls", "assumeClosedWorld", "assumeImmutableTables");
            Set<String> tables = Set.copyOf(options.strings("assumeImmutableTables"));
            for (String field : tables) if (!field.matches("L[^;]+;->[^:]+:\\[S"))
               throw new IllegalArgumentException("assumeImmutableTables requires exact short[] field signatures");
            return new NpCleanup(options.bool("removeProtectedStringCalls"), options.bool("assumeClosedWorld"), tables);
        }
    }
}
