package me.naptila.deobfuscator.transformers.np.methodhiding;

import java.util.*;

import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.transform.TransformerProvider;
import me.naptila.deobfuscator.transformers.np.NpTransformer;
import me.naptila.deobfuscator.transformers.np.analysis.NpAnalysis;
import me.naptila.deobfuscator.transformers.np.analysis.NpHelpers;
import me.naptila.deobfuscator.transformers.np.analysis.NpModel;
import me.naptila.deobfuscator.transformers.np.support.ProxyAccess;
import me.naptila.deobfuscator.transformers.np.support.ProxyInstructions;
import me.naptila.deobfuscator.transformers.np.strings.NpStringCalls;

import org.jf.dexlib2.AccessFlags;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.BuilderInstruction;
import org.jf.dexlib2.builder.instruction.BuilderInstruction10x;
import org.jf.dexlib2.builder.instruction.BuilderInstruction11x;
import org.jf.dexlib2.builder.instruction.BuilderInstruction22c;
import org.jf.dexlib2.builder.instruction.BuilderInstruction3rc;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.instruction.TwoRegisterInstruction;
import org.jf.dexlib2.iface.instruction.VariableRegisterInstruction;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.Reference;
import org.jf.dexlib2.iface.reference.StringReference;
import org.jf.dexlib2.iface.reference.TypeReference;
import org.jf.dexlib2.immutable.*;

public final class MethodHidingTransformer implements DexPass {
   private HiddenProxies proxies;
   private final LibraryTypes libraries;
   private final boolean inlineProtected;
   private MemberResolver resolver;
   private Set<String> proxyOwners = Set.of();

   public MethodHidingTransformer() {
      this(List.of(), true);
   }

   public MethodHidingTransformer(List<String> classpath, boolean inlineProtected) {
      this.libraries = new LibraryTypes(classpath);
      this.inlineProtected = inlineProtected;
   }

   @Override
   public String id() {
      return "np.method-hiding";
   }

   @Override
   public void prepare(DexContext dex) {
      this.prepareFacts(dex, NpAnalysis.of(dex).model(), true);
   }

   public void prepareFacts(DexContext dex, NpModel model, boolean recordProofs) {
      this.proxies = new HiddenProxies(dex, model);
      this.resolver = new MemberResolver(dex, this.libraries);
      Set<String> owners = new HashSet<>();
      for (var template : this.proxies.templates.values()) owners.add(template.method().getDefiningClass());
      this.proxyOwners = Set.copyOf(owners);
      if (recordProofs) {
         for (HiddenProxies.Template template : this.proxies.templates.values()) {
            MethodReference guard = template.guard();
            List<String> facts = new ArrayList<>();
            if (template.classProxy()) {
               facts.add("proxyClass=" + template.method().getDefiningClass());
               facts.add("classShape=Object superclass; no interfaces; one static integer; optional private final short table; public static methods");
               facts.add("helperSemantics=verified hash, integer guard and short-array decoder; String-to-String helper present");
               facts.add("body=bounded statically selected trace; member operation order preserved");
            } else {
               facts.add("body=statically selected single literal/member operation");
            }
            String owner = template.method().getDefiningClass();
            if (!ProxyAccess.initializationSafe(dex, owner, "") && initializationSafe(dex, owner, ""))
               facts.add("proxyInitialization=verified empty initializer or private final short table; allocation failures may differ");
            if (guard != null) {
               facts.add("verifiedGuard=" + Signatures.of(guard));
               if (!template.classProxy()) facts.add("guardBranch=statically selected");
            }
            facts.add("parameterReads=validated");
            facts.add("proxyCycles=excluded");
            dex.evidence()
               .register(
                  dex,
                  template.method(),
                  this.id(),
                  template.classProxy() ? "np.class-proxy.trace.v1" : template.traced() ? "np.guarded-proxy.trace.v1" : "np.guarded-proxy.v1",
                  facts
               );
         }
      }
   }

   public PassResult run(MethodContext context) {
      if (this.proxies == null) {
         throw new IllegalStateException("NP proxies require preparation");
      }

      CodeGraph g = context.graph();
      int invocation = context.nextInvocation(this.id());
      List<Edits.Edit> edits = new ArrayList<>();
      int calls = 0;
      int literals = 0;
      int scratch = 0;
      Map<String, Integer> retained = new TreeMap<>();
      Map<String, BitSet> initialized = null;
      List<BuilderInstruction> obsoleteResults = new ArrayList<>();
      RegisterLiveness live = null;
      String caller = context.original().getDefiningClass();
      int incoming = context.original().getParameterTypes().stream().mapToInt(t -> ProxyInstructions.wide(t.toString()) ? 2 : 1).sum()
            + (AccessFlags.STATIC.isSet(context.original().getAccessFlags()) ? 0 : 1);

      for (int index = 0; index < g.size(); index++) {
         Instruction insn = g.at(index);
         if (insn.getOpcode() == Opcode.INVOKE_STATIC || insn.getOpcode() == Opcode.INVOKE_STATIC_RANGE) {
            MethodReference ref = (MethodReference)((ReferenceInstruction)insn).getReference();
            HiddenProxies.Template template = this.proxies.templates.get(Signatures.of(ref));
            if (template == null) {
               if (this.proxies.unresolved.contains(Signatures.of(ref))) retained.merge("body proof unavailable", 1, Integer::sum);
               continue;
            }
            if (!this.inlineProtected && !g.protection(index).isEmpty()) {
               retained.merge("try protection; inlineProtected=false", 1, Integer::sum);
               continue;
            }
            String owner = template.method().getDefiningClass();
            if (initialized == null && !initializationSafe(context.dex(), owner, caller)) {
               initialized = ProxyAccess.initializedBefore(context, g, this.proxyOwners);
            }
            String access = this.access(context, template, initialized == null ? null : initialized.get(owner), index);
            if (access != null) {
               retained.merge(access, 1, Integer::sum);
               continue;
            }
            {
               int result = -1;
               if (index + 1 < g.size() && g.at(index + 1).getOpcode().name.startsWith("move-result")) {
                  if (g.leaders().contains(index + 1) || !this.inlineProtected && !g.protection(index + 1).isEmpty()) {
                     retained.merge("result boundary", 1, Integer::sum);
                     continue;
                  }

                  result = NpHelpers.reg(g.at(index + 1));
               }

               List<BuilderInstruction> replacement = new ArrayList<>();
               List<Instruction> body = template.body();
               boolean literal = body.size() == 1
                  && (body.get(0).getOpcode() == Opcode.CONST_STRING || body.get(0).getOpcode() == Opcode.CONST_STRING_JUMBO)
                  && template.returned().getOpcode() == Opcode.RETURN_OBJECT
                  && NpHelpers.reg(body.get(0)) == NpHelpers.reg(template.returned());
               if (literal) {
                  if (result < 0) {
                     retained.merge("unused literal result", 1, Integer::sum);
                     continue;
                  }

                  replacement.add(Edits.constant(result, ((StringReference)((ReferenceInstruction)body.get(0)).getReference()).getString()));
               } else {
                  int count = template.registers();
                  if (live == null) {
                     live = new RegisterLiveness(g);
                  }

                  int base = -1;

                  for (int start = 0; start + count <= Math.min(256, g.registers()); start++) {
                     boolean dead = true;

                     for (int r = start; r < start + count; r++) {
                        if (live.liveBefore(index, r)) {
                           dead = false;
                           break;
                        }
                     }

                     for (int r = start; r < start + count; r++) {
                        if (live.liveAfter(index, r)) {
                           dead = false;
                           break;
                        }
                     }

                     if (dead) {
                        base = start;
                        break;
                     }
                  }

                  boolean grow = base < 0;
                  if (grow) {
                     base = g.registers();
                  }

                  if (base + count > 256) {
                     retained.merge("register limit", 1, Integer::sum);
                     continue;
                  }

                  int[] args = ConstantEvaluator.arguments(insn);
                  int words = template.method().getParameterTypes().stream().mapToInt(t -> ProxyInstructions.wide(t.toString()) ? 2 : 1).sum();
                  if (words != args.length) {
                     retained.merge("argument word count", 1, Integer::sum);
                     continue;
                  }

                  int param = count - words;
                  int arg = 0;
                  int packed = 0;
                  BitSet lowFree = new BitSet(16);
                  for (int r = 0; r < Math.min(16, g.registers()); r++) {
                     if ((r < base || r >= base + count) && !live.liveBefore(index, r) && !live.liveAfter(index, r)) lowFree.set(r);
                  }

                  for (CharSequence type : template.method().getParameterTypes()) {
                     replacement.add(ProxyInstructions.move(base + param, args[arg], type.toString()));
                     int width = ProxyInstructions.wide(type.toString()) ? 2 : 1;
                     param += width;
                     arg += width;
                  }

                  boolean supported = true;
                  boolean directResult = false;

                  for (int bodyIndex = 0; bodyIndex < body.size(); bodyIndex++) {
                     Instruction step = body.get(bodyIndex);
                     boolean tailResult = result >= 0
                        && g.protection(index).equals(g.protection(index + 1))
                        && bodyIndex == body.size() - 1
                        && step.getOpcode().name.startsWith("move-result")
                        && template.returned().getOpcode() != Opcode.RETURN_VOID
                        && NpHelpers.reg(step) == NpHelpers.reg(template.returned());
                     BuilderInstruction copy = (BuilderInstruction)(tailResult
                        ? new BuilderInstruction11x(step.getOpcode(), result)
                        : ProxyInstructions.copy(step, base));
                     if (copy != null) replacement.add(copy);
                     else {
                        List<BuilderInstruction> expanded = expandMember(step, base, g.registers() + (grow ? count : 0), lowFree);
                        if (expanded == null) { supported = false; break; }
                        replacement.addAll(expanded);
                        if (step instanceof VariableRegisterInstruction) packed = Math.max(packed, ConstantEvaluator.arguments(step).length);
                     }
                     directResult |= tailResult;
                  }

                  if (!supported) {
                     retained.merge("instruction encoding", 1, Integer::sum);
                     continue;
                  }

                  if (result >= 0 && !directResult) {
                     if (template.returned().getOpcode() == Opcode.RETURN_VOID) {
                        continue;
                     }

                     replacement.add(ProxyInstructions.move(result, base + NpHelpers.reg(template.returned()), ref.getReturnType()));
                  }

                  if ((grow || packed > 0) && (long) g.registers() + (grow ? count : 0) + packed + incoming > 65535) {
                     retained.merge("register limit", 1, Integer::sum);
                     continue;
                  }
                  scratch = Math.max(scratch, (grow ? count : 0) + packed);
               }

               if (!replacement.isEmpty()) {
                  edits.add(new Edits.Edit(index, false, replacement));
                  if (result >= 0) {
                     BuilderInstruction placeholder = new BuilderInstruction10x(Opcode.NOP);
                     obsoleteResults.add(placeholder);
                     edits.add(new Edits.Edit(index + 1, false, List.of(placeholder)));
                  }

                  calls++;
                  if (literal) {
                     literals++;
                  }

                  context.recordReplacement(this.id(), Signatures.of(ref), invocation, index, g.address(index));
               }
            }
         }
      }

      Edits.apply(context.code(), edits);
      BitSet remove = new BitSet();

      for (BuilderInstruction obsolete : obsoleteResults) {
         remove.set(obsolete.getLocation().getIndex());
      }

      ExceptionEdits.remove(context, remove);
      if (scratch > 0) {
         context.appendScratchRegisters(scratch);
      }

      List<String> notes = new ArrayList<>();
      if (calls != 0) {
         notes.add("NP proxies restored: " + calls);
         notes.add("NP literal proxies restored: " + literals);
      }
      retained.forEach((reason, count) -> notes.add("NP proxy calls retained (" + reason + "): " + count));
      return new PassResult(calls, notes);
   }

   /** Encode members that need low field operands or a contiguous invoke argument list. */
   private static List<BuilderInstruction> expandMember(Instruction step, int base, int packedBase, BitSet lowFree) {
      Opcode op = step.getOpcode();
      if (!(step instanceof ReferenceInstruction ref)) return null;
      List<BuilderInstruction> result = new ArrayList<>();
      if (step instanceof VariableRegisterInstruction && ref.getReference() instanceof MethodReference method) {
         Opcode range = switch (op) {
            case INVOKE_STATIC, INVOKE_STATIC_RANGE -> Opcode.INVOKE_STATIC_RANGE;
            case INVOKE_VIRTUAL, INVOKE_VIRTUAL_RANGE -> Opcode.INVOKE_VIRTUAL_RANGE;
            case INVOKE_INTERFACE, INVOKE_INTERFACE_RANGE -> Opcode.INVOKE_INTERFACE_RANGE;
            case INVOKE_DIRECT, INVOKE_DIRECT_RANGE -> Opcode.INVOKE_DIRECT_RANGE;
            default -> null;
         };
         if (range == null) return null;
         int[] args = ConstantEvaluator.arguments(step);
         if ((long) packedBase + args.length > 65535) return null;
         List<String> types = new ArrayList<>();
         if (range != Opcode.INVOKE_STATIC_RANGE) types.add(method.getDefiningClass());
         method.getParameterTypes().forEach(t -> types.add(t.toString()));
         int word = 0;
         for (String type : types) {
            int width = ProxyInstructions.wide(type) ? 2 : 1;
            if (word + width > args.length || width == 2 && args[word + 1] != args[word] + 1) return null;
            result.add(ProxyInstructions.move(packedBase + word, base + args[word], type));
            word += width;
         }
         if (word != args.length) return null;
         result.add(new BuilderInstruction3rc(range, packedBase, args.length, method));
         return result;
      }
      if (step instanceof TwoRegisterInstruction two && ref.getReference() instanceof FieldReference field
            && (op.name.startsWith("iget") || op.name.startsWith("iput"))) {
         int width = ProxyInstructions.wide(field.getType()) ? 2 : 1;
         int value = -1;
         for (int r = 0; r + width <= 16; r++) {
            if (lowFree.get(r) && (width == 1 || lowFree.get(r + 1))) { value = r; break; }
         }
         if (value < 0) return null;
         BitSet available = (BitSet) lowFree.clone();
         available.clear(value, value + width);
         int receiver = available.nextSetBit(0);
         if (receiver < 0) return null;
         boolean get = op.name.startsWith("iget");
         if (!get) result.add(ProxyInstructions.move(value, base + two.getRegisterA(), field.getType()));
         result.add(ProxyInstructions.move(receiver, base + two.getRegisterB(), field.getDefiningClass()));
         result.add(new BuilderInstruction22c(op, value, receiver, field));
         if (get) result.add(ProxyInstructions.move(base + two.getRegisterA(), value, field.getType()));
         return result;
      }
      return null;
   }

   private String access(MethodContext context, HiddenProxies.Template template, BitSet initialized, int index) {
      String caller = context.original().getDefiningClass();
      String owner = template.method().getDefiningClass();
      if (!initializationSafe(context.dex(), owner, caller) && (initialized == null || !initialized.get(index)))
         return "proxy class initialization";
      if (ProxyAccess.member(context.dex(), this.resolver, template.method(), caller, false)) {
         for (Instruction i : template.body()) {
            if (i instanceof ReferenceInstruction r) {
               Reference ref = r.getReference();
               if (ref instanceof TypeReference t && !ProxyAccess.type(context.dex(), this.resolver, t.getType(), caller)) {
                  return "type metadata or access; check classpath";
               }

               if ((ref instanceof MethodReference || ref instanceof FieldReference)
                  && !ProxyAccess.member(
                     context.dex(), this.resolver, ref, caller, i.getOpcode().name.startsWith("iput") || i.getOpcode().name.startsWith("sput")
                  )) {
                  return "member metadata or access; check classpath";
               }

               if (i.getOpcode().name.startsWith("invoke-direct") && ref instanceof MethodReference m && !m.getDefiningClass().equals(caller)) {
                  return "invoke-direct owner";
               }
            }
         }

         return null;
      } else {
         return "proxy access";
      }
   }

   private boolean initializationSafe(DexContext dex, String owner, String caller) {
      return ProxyAccess.initializationSafe(dex, owner, caller)
         || proxies.proxyClasses.contains(owner) && NpStringCalls.initializationSafe(dex, owner, caller);
   }

    public static final class Provider extends NpTransformer.Provider {
        public String id() { return "np.method-hiding"; }
        public String displayName() { return "Method hiding recovery"; }
        public String description() { return "Restore verified guarded proxies, literals, and member operations."; }
        public DexPass create(TransformerOptions options) {
            options.requireOnly("classpath", "inlineProtected", "assumeClosedWorld", "keepMethods");
            options.bool("assumeClosedWorld");
            options.strings("keepMethods");
            return new MethodHidingTransformer(options.strings("classpath"),
                  !options.values().containsKey("inlineProtected") || options.bool("inlineProtected"));
        }
        @Override
        public List<TransformerSpec> cleanup(TransformerOptions options) {
            var steps = new ArrayList<>(super.cleanup(options));
            var cleanup = TransformerOptions.empty();
            for (String key : List.of("assumeClosedWorld", "keepMethods"))
                if (options.values().containsKey(key)) cleanup = cleanup.with(key, options.values().get(key));
            steps.add(new TransformerSpec("np.method-hiding.cleanup", cleanup));
            return List.copyOf(steps);
        }
    }

    public static final class Cleanup implements DexPass, DexFinalizer {
        private final boolean closedWorld;
        private final Set<String> keep;
        public Cleanup() { this(false, List.of()); }
        public Cleanup(boolean closedWorld, List<String> keep) { this.closedWorld = closedWorld; this.keep = Set.copyOf(keep); }
        public String id() { return "np.method-hiding.cleanup"; }
        public Phase phase() { return Phase.REMOVE_DEFINITIONS; }
        // Run on incomplete inputs to report why definitions are retained, not to remove them.
        public boolean requiresCompleteMethods() { return false; }
        public void prepare(DexContext dex) {
            for (String signature : keep) if (!dex.methods().containsKey(signature)) throw new IllegalArgumentException("Unknown keepMethods entry: " + signature);
        }
        public PassResult run(MethodContext context) { return PassResult.unchanged(); }
        public Result finish(DexContext original, DexFile rewritten) {
            var ledger = original.evidence(); var evidence = ledger.snapshot();
            var candidates = new TreeMap<String, TransformationEvidence.Candidate>();
            for (var candidate : evidence.candidates()) if (candidate.producer().equals("np.method-hiding")
                    && Set.of("np.guarded-proxy.v1", "np.guarded-proxy.trace.v1", "np.class-proxy.trace.v1").contains(candidate.rule()))
                candidates.put(candidate.method(), candidate);
            if (candidates.isEmpty()) return new Result(rewritten, PassResult.skipped("No restoration provenance; run np.method-hiding in the same pipeline"));
            DexContext output = new DexContext(rewritten); var references = new MethodReferences(output);
            List<String> hazards = DynamicMethodAccess.hazards(output, references);
            Map<String, Set<String>> reasons = new TreeMap<>(), incoming = new TreeMap<>(), edges = new TreeMap<>();
            Map<String, String> hashes = new HashMap<>();
            Set<String> roots = new TreeSet<>();
            for (var candidate : candidates.values()) {
                String signature = candidate.method(); Method method = output.methods().get(signature);
                reasons.put(signature, new TreeSet<>()); incoming.put(signature, new TreeSet<>()); edges.put(signature, new TreeSet<>());
                if (method == null) { reasons.get(signature).add("ALREADY_ABSENT"); continue; }
                String hash = MethodFingerprint.of(output, method); hashes.put(signature, hash);
                if (!candidate.originalSha256().equals(MethodFingerprint.of(original, original.methods().get(signature)))) reasons.get(signature).add("ORIGINAL_FINGERPRINT_MISMATCH");
                if (!Objects.equals(hash, ledger.acceptedFingerprint(signature))) reasons.get(signature).add("OUTPUT_CHANGED_AFTER_TRANSACTION_OR_UNCOMMITTED");
                if (!evidence.incompleteMethods().isEmpty()) reasons.get(signature).add("INCOMPLETE_METHOD_TRANSACTIONS");
                if (!closedWorld && !AccessFlags.PRIVATE.isSet(method.getAccessFlags())) reasons.get(signature).add("EXTERNAL_ENTRY_NOT_EXCLUDED");
                if (!AccessFlags.STATIC.isSet(method.getAccessFlags()) || method.getName().startsWith("<") || AccessFlags.NATIVE.isSet(method.getAccessFlags())) reasons.get(signature).add("UNSUPPORTED_ENTRY_KIND");
                if (keep.contains(signature)) reasons.get(signature).add("EXPLICIT_KEEP");
                if (!hazards.isEmpty()) reasons.get(signature).add("DYNAMIC_METHOD_ACCESS_NOT_EXCLUDED");
                if (references.strings().contains(method.getName())) reasons.get(signature).add("METHOD_NAME_STRING_PRESENT");
                if (!reasons.get(signature).isEmpty()) roots.add(signature);
            }
            // Metadata/handles are roots even when stored inside another candidate. Direct proxy edges
            // participate in reachability, so an entire unused component can be removed together.
            Map<String, List<String>> byDescriptor = new HashMap<>();
            for (String signature : candidates.keySet()) {
                Method method = output.methods().get(signature);
                if (method != null) byDescriptor.computeIfAbsent(descriptor(method), key -> new ArrayList<>()).add(signature);
            }
            for (var use : references.uses()) for (String signature : byDescriptor.getOrDefault(descriptor(use.method()), List.of())) {
                Method candidate = output.methods().get(signature);
                if (candidate == null || !MethodReferences.mayResolveTo(output, use.method(), candidate)) continue;
                incoming.get(signature).add(use.kind() + " from " + use.source() + " via " + Signatures.of(use.method()));
                if (use.directCall() && candidates.containsKey(use.source())) edges.get(use.source()).add(signature);
                else { roots.add(signature); reasons.get(signature).add(use.directCall() ? "REFERENCED_BY_RETAINED_METHOD" : "METADATA_OR_HANDLE_REFERENCE"); }
            }
            ArrayDeque<String> work = new ArrayDeque<>(roots); Set<String> live = new TreeSet<>(roots);
            while (!work.isEmpty()) for (String target : edges.get(work.removeFirst())) if (live.add(target)) {
                reasons.get(target).add("REACHABLE_FROM_RETAINED_PROXY"); work.add(target);
            }
            Set<String> removed = new TreeSet<>();
            for (String signature : candidates.keySet()) {
                String action;
                if (!output.methods().containsKey(signature)) action = "alreadyAbsent";
                else if (live.contains(signature)) action = "retained";
                else { action = "deleted"; removed.add(signature); reasons.get(signature).add("RECORDED_PROXY_WITH_NO_RETAINED_ENTRY_OR_REFERENCE"); }
                ledger.decide(new TransformationEvidence.Decision(signature, action, hashes.get(signature), new ArrayList<>(reasons.get(signature)), new ArrayList<>(incoming.get(signature))));
            }
            List<ClassDef> classes = new ArrayList<>();
            for (ClassDef cls : rewritten.getClasses()) {
                List<Method> direct = new ArrayList<>(), virtual = new ArrayList<>();
                for (Method method : cls.getDirectMethods()) if (!removed.contains(Signatures.of(method))) direct.add(method);
                for (Method method : cls.getVirtualMethods()) if (!removed.contains(Signatures.of(method))) virtual.add(method);
                classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(), cls.getStaticFields(), cls.getInstanceFields(), direct, virtual));
            }
            var result = new ImmutableDexFile(rewritten.getOpcodes(), classes);
            // Independent postcondition: no surviving explicit reference may point at a removed method.
            if (!removed.isEmpty()) {
                Map<String, List<String>> removedByDescriptor = new HashMap<>();
                for (String signature : removed) removedByDescriptor.computeIfAbsent(descriptor(output.methods().get(signature)), key -> new ArrayList<>()).add(signature);
                var finalReferences = new MethodReferences(new DexContext(result));
                for (var use : finalReferences.uses()) for (String signature : removedByDescriptor.getOrDefault(descriptor(use.method()), List.of()))
                    if (signature.equals(Signatures.of(use.method())) || MethodReferences.mayResolveTo(output, use.method(), output.methods().get(signature)))
                        throw new IllegalStateException("Dangling proxy reference: " + signature);
            }
            List<String> notes = new ArrayList<>(List.of("Recorded NP proxies: " + candidates.size(), "Proxy definitions removed: " + removed.size(),
                    "Proxy definitions retained: " + live.size(), "assumeClosedWorld=" + closedWorld,
                    "Classes, fields and initializers are retained"));
            for (String hazard : hazards) notes.add("Dynamic access: " + hazard);
            return new Result(result, new PassResult(removed.size(), notes));
        }
        /** Owner intentionally excluded: inherited and unresolved owners still need the original proof. */
        private static String descriptor(org.jf.dexlib2.iface.reference.MethodReference method) {
            return method.getName() + "(" + String.join("", method.getParameterTypes()) + ")" + method.getReturnType();
        }
    }

    public static final class CleanupProvider implements TransformerProvider {
        public boolean internal() { return true; }
        public String id() { return "np.method-hiding.cleanup"; }
        public String description() { return "Remove recorded NP proxy definitions after final reference and entry-point checks"; }
        public DexPass create(TransformerOptions options) {
            options.requireOnly("assumeClosedWorld", "keepMethods");
            return new Cleanup(options.bool("assumeClosedWorld"), options.strings("keepMethods"));
        }
    }
}
