package me.naptila.deobfuscator.transformers.np.reflection;

import java.util.*;

import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.transformers.np.NpTransformer;
import me.naptila.deobfuscator.transformers.np.support.ProxyAccess;

import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;
import org.jf.dexlib2.immutable.*;

/** NP8 opt-in runtime specialization, without executing the input or relaxing access flags. */
public final class ReflectionTransformer implements DexPass, DexFinalizer {
    private final LibraryTypes libraries;
    private final boolean enabled;
    private final boolean closedWorld;
    private ReflectionModel model;
    private MemberResolver resolver;
    private final Map<String, Method> generated = new TreeMap<>();
    private final Map<String, FieldReference> fieldReaders = new HashMap<>();
    private final Map<String, Boolean> stringHelpers = new HashMap<>();
    public ReflectionTransformer() { this(List.of(), false); }
    public ReflectionTransformer(List<String> classpath, boolean enabled) { this(classpath, enabled, false); }
    public ReflectionTransformer(List<String> classpath, boolean enabled, boolean closedWorld) {
        libraries = new LibraryTypes(classpath); this.enabled = enabled; this.closedWorld = closedWorld;
    }
    public String id() { return "np.reflection"; }
    public void prepare(DexContext dex) { model = new ReflectionModel(dex); resolver = new MemberResolver(dex, libraries); generated.clear(); fieldReaders.clear(); stringHelpers.clear(); }
    public PassResult run(MethodContext context) {
        if (!enabled) return PassResult.unchanged();
        // Never specialize the dispatcher/runtime itself or an already linked adapter on a rerun.
        if (context.original().getName().startsWith("np$resolved$") || model.dispatchers.containsKey(context.name())) return PassResult.unchanged();
        int strings = restoreStrings(context);
        int direct = 0, changed;
        DirectReflectionCalls calls = new DirectReflectionCalls(model, resolver, (member, resolved, caller) -> accessor(context.dex(), member, resolved, caller));
        do { changed = calls.run(context); direct += changed; } while (changed > 0);
        int fields = DirectReflectionCalls.fields(context, resolver, fieldReaders);
        int literals = ReflectionTransformer.cleanStrings(context, stringHelpers);
        int scaffolding = (direct > 0 || strings > 0 || fields > 0 || literals > 0) ? ReflectionTransformer.cleanScaffolding(context) : 0;
        CodeGraph g = context.graph(); ConstantAnalysis constants = null; List<Edits.Edit> edits = new ArrayList<>();
        for (int i = 0; i < g.size(); i++) {
            Instruction insn = g.at(i);
            if (insn.getOpcode() != Opcode.INVOKE_STATIC && insn.getOpcode() != Opcode.INVOKE_STATIC_RANGE) continue;
            var entries = model.dispatchers.get(Signatures.of(ReflectionModel.methodRef(insn))); if (entries == null) continue;
            if (constants == null) constants = new ConstantAnalysis(g, ConstantEvaluator::step, false, true);
            int[] args = ConstantEvaluator.arguments(insn); Constants state = constants.before(i);
            if (state == null || !(state.get(args[0]) instanceof Integer id)) continue;
            var entry = entries.get(id); if (entry == null) continue;
            Method bridge = bridge(context.dex(), context.original().getDefiningClass(), entry); if (bridge == null) continue;
            org.jf.dexlib2.builder.BuilderInstruction replacement;
            if (insn instanceof RegisterRangeInstruction range) replacement = new BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, range.getStartRegister(), range.getRegisterCount(), bridge);
            else { var r = (FiveRegisterInstruction)insn; replacement = new BuilderInstruction35c(Opcode.INVOKE_STATIC, r.getRegisterCount(), r.getRegisterC(), r.getRegisterD(), r.getRegisterE(), r.getRegisterF(), r.getRegisterG(), bridge); }
            edits.add(new Edits.Edit(i, false, List.of(replacement)));
        }
        Edits.apply(context.code(), edits);
        boolean relevant = false;
        for (Instruction i : context.original().getImplementation().getInstructions())
            if (i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m && model.dispatchers.containsKey(Signatures.of(m))) { relevant = true; break; }
        int separated = 0;
        if (relevant) while (HandlerValueRegisters.run(context) > 0) separated++;
        int flow = separated + (relevant ? BranchThreading.run(context) + SwitchDefaults.run(context) + SwitchDefaultEdges.run(context)
                + HandlerEntries.run(context) + SharedConditionalRegions.run(context) + HandlerLiteralRegisters.run(context) : 0);
        return edits.isEmpty() && flow == 0 && direct == 0 && scaffolding == 0 && strings == 0 && fields == 0 && literals == 0 ? PassResult.unchanged() : new PassResult(edits.size() + flow + direct + scaffolding + strings + fields + literals,
                List.of("Direct field reads: " + fields, "Content-only string literals: " + literals, "Visible cached string literals: " + strings, "Direct typed reflection calls: " + direct, "Dead reflection scaffolding: " + scaffolding, "Guarded fallback call sites: " + edits.size(), "Reflection caller control-flow edits: " + flow));
    }
    private int restoreStrings(MethodContext context) {
        CodeGraph g = context.graph(); RegisterLiveness live = new RegisterLiveness(g); boolean scratch = false;
        BitSet handlerLive = new BitSet();
        for (var block : context.code().getTryBlocks()) {
            int target = g.index(block.exceptionHandler.getHandlerCodeAddress());
            for (int r = 0; r < g.registers(); r++) if (live.liveBefore(target, r)) handlerLive.set(r);
        }
        ConstantAnalysis constants = null; List<Edits.Edit> edits = new ArrayList<>();
        for (int i = 0; i < g.size(); i++) {
            Instruction insn = g.at(i);
            if (insn.getOpcode() != Opcode.INVOKE_STATIC && insn.getOpcode() != Opcode.INVOKE_STATIC_RANGE) continue;
            var entries = model.dispatchers.get(Signatures.of(ReflectionModel.methodRef(insn))); if (entries == null) continue;
            if (constants == null) constants = new ConstantAnalysis(g, ConstantEvaluator::step, false, true);
            Constants state = constants.before(i); int[] args = ConstantEvaluator.arguments(insn);
            if (state == null || !(state.get(args[0]) instanceof Integer id)) continue;
            var entry = entries.get(id); if (entry == null || entry.target().text() == null) continue;
            int bank = -1;
            for (int r = 0; r + 1 < Math.min(256, g.registers()); r++) if (!handlerLive.get(r) && !handlerLive.get(r + 1) && !live.liveAfter(i, r) && !live.liveAfter(i, r + 1)) { bank = r; break; }
            if (bank < 0) { if (g.registers() > 254) continue; bank = g.registers(); scratch = true; }
            String name = entry.target().interned() ? "np$resolved$stringLiteral" : "np$resolved$string";
            Method method = ReflectionCode.cachedString(name, entry); String sig = Signatures.of(method);
            if (context.dex().methods().containsKey(sig)) continue;
            generated.putIfAbsent(sig, method); stringHelpers.put(sig, entry.target().interned());
            edits.add(new Edits.Edit(i, false, List.of(Edits.constant(bank, id), Edits.constant(bank + 1, entry.target().text()),
                    new BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, bank, 2, method))));
        }
        Edits.apply(context.code(), edits); if (scratch) context.appendScratchRegisters(2);
        return edits.size();
    }
    private Method accessor(DexContext dex, Reference ref, MemberResolver.Member resolved, String caller) {
        String owner;
        if (ProxyAccess.member(dex, resolver, ref, caller, false)) owner = caller;
        else if (dex.classes().containsKey(resolved.owner()) && ProxyAccess.type(dex, resolver, resolved.owner(), caller)) owner = resolved.owner();
        else return null;
        if (!ProxyAccess.member(dex, resolver, ref, owner, false)) return null;
        List<String> types = new ArrayList<>();
        if (ref instanceof MethodReference m) { types.add(m.getReturnType()); m.getParameterTypes().forEach(t -> types.add(t.toString())); }
        else types.add(((FieldReference)ref).getType());
        for (String type : types) if (!ProxyAccess.type(dex, resolver, type, owner) || !ProxyAccess.type(dex, resolver, type, caller)) return null;
        String label = ref instanceof MethodReference m ? m.getName() : "get$" + ((FieldReference)ref).getName();
        String seed = ref.toString();
        String name = "access$np$" + label + "$" + UUID.nameUUIDFromBytes(seed.getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString().replace("-", "");
        Method method = ReflectionCode.typed(owner, name, ref, resolved); if (method == null) return null;
        String sig = Signatures.of(method);
        if (dex.methods().containsKey(sig)) return null;
        if (ref instanceof FieldReference field) fieldReaders.put(sig, field);
        return generated.computeIfAbsent(sig, key -> method);
    }
    private Method bridge(DexContext dex, String caller, ReflectionModel.Entry entry) {
        Reference ref = entry.target().member(); String owner = entry.dispatcher().getDefiningClass(); String label = "string";
        MemberResolver.Member resolved = null;
        if (ref != null) {
            resolved = resolver.resolve(ref); if (resolved == null) return null;
            // invoke-direct/interface cannot name a different, inheriting class as their owner.
            if (ref instanceof MethodReference m && (AccessFlags.PRIVATE.isSet(resolved.flags()) || AccessFlags.INTERFACE.isSet(resolved.ownerFlags()))
                    && !m.getDefiningClass().equals(resolved.owner())) return null;
            label = ref instanceof MethodReference m ? m.getName() : "get$" + ((FieldReference)ref).getName();
            if (label.startsWith("<")) return null;
            if (ProxyAccess.member(dex, resolver, ref, caller, false)) owner = caller;
            else if (dex.classes().containsKey(resolved.owner()) && ProxyAccess.type(dex, resolver, resolved.owner(), caller)) owner = resolved.owner();
            else return null;
            if (!ProxyAccess.member(dex, resolver, ref, owner, false)) return null;
            List<String> types = new ArrayList<>();
            if (ref instanceof MethodReference m) { types.add(m.getReturnType()); m.getParameterTypes().forEach(t -> types.add(t.toString())); }
            else types.add(((FieldReference)ref).getType());
            for (String type : types) if (!ProxyAccess.type(dex, resolver, type, owner)) return null;
        }
        String seed = Signatures.of(entry.dispatcher()) + ":" + entry.id();
        String name = "np$resolved$" + label + "$" + UUID.nameUUIDFromBytes(seed.getBytes(java.nio.charset.StandardCharsets.UTF_8)).toString().replace("-", "");
        String sig = owner + "->" + name + "(" + String.join("", entry.dispatcher().getParameterTypes()) + ")Ljava/lang/Object;";
        if (generated.containsKey(sig)) return generated.get(sig);
        if (dex.methods().containsKey(sig)) return null;
        Method method = ref == null ? ReflectionCode.string(name, entry) : ReflectionCode.member(owner, name, entry, resolved);
        if (method != null) generated.put(sig, method); return method;
    }
    public boolean requiresCompleteMethods() { return false; }
    public Phase phase() { return Phase.LINK; }
    public Result finish(DexContext original, DexFile rewritten) {
        Set<String> needed = new HashSet<>(); ArrayDeque<Method> work = new ArrayDeque<>();
        for (ClassDef cls : rewritten.getClasses()) cls.getMethods().forEach(work::add);
        while (!work.isEmpty()) {
            Method method = work.removeFirst(); if (method.getImplementation() == null) continue;
            for (Instruction i : method.getImplementation().getInstructions()) if (i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m) {
                String sig = Signatures.of(m);
                if (generated.containsKey(sig) && needed.add(sig)) work.add(generated.get(sig));
            }
        }
        List<ClassDef> classes = new ArrayList<>();
        for (ClassDef cls : rewritten.getClasses()) {
            List<Method> direct = new ArrayList<>(); cls.getDirectMethods().forEach(direct::add);
            for (Method m : generated.values()) if (needed.contains(Signatures.of(m)) && m.getDefiningClass().equals(cls.getType())) direct.add(m);
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(), cls.getStaticFields(), cls.getInstanceFields(), direct, cls.getVirtualMethods()));
        }
        DexFile linked = new ImmutableDexFile(rewritten.getOpcodes(), classes);
        List<String> notes = new ArrayList<>(); int fieldLiterals = 0;
        if (enabled && closedWorld && original.evidence().snapshot().incompleteMethods().isEmpty()) {
            var cleanup = PrivateStringFields.clean(linked, original, model, stringHelpers);
            linked = cleanup.dex(); fieldLiterals = cleanup.edits(); notes.addAll(cleanup.notes());
            if (fieldLiterals > 0) {
                DexContext snapshot = new DexContext(linked); needed.clear(); work.clear();
                for (Method m : snapshot.methods().values()) if (!generated.containsKey(Signatures.of(m))) work.add(m);
                while (!work.isEmpty()) {
                    Method m = work.removeFirst(); if (m.getImplementation() == null) continue;
                    for (Instruction i : m.getImplementation().getInstructions()) if (i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference target) {
                        String sig = Signatures.of(target);
                        if (generated.containsKey(sig) && needed.add(sig) && snapshot.methods().containsKey(sig)) work.add(snapshot.methods().get(sig));
                    }
                }
                List<ClassDef> retained = new ArrayList<>();
                for (ClassDef cls : linked.getClasses()) {
                    List<Method> methods = new ArrayList<>();
                    for (Method m : cls.getMethods()) if (!generated.containsKey(Signatures.of(m)) || needed.contains(Signatures.of(m))) methods.add(m);
                    retained.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
                }
                linked = new ImmutableDexFile(linked.getOpcodes(), retained);
            }
        } else notes.add("Private string field cleanup retained: " + (!closedWorld ? "assumeClosedWorld is false" : "incomplete or disabled restoration"));
        notes.add("Referenced NP adapters linked: " + needed.size());
        notes.add("Original runtime retained for argument-validation fallbacks");
        return new Result(linked, new PassResult(needed.size() + fieldLiterals, notes));
    }

    public static final class Provider extends NpTransformer.Provider {
        public String id() { return "np.reflection"; }
        public String displayName() { return "Reflection recovery"; }
        public String description() { return "Recover verified cached reflection calls. Requires classpath and assumeStandardRuntime options."; }
        public DexPass create(TransformerOptions options) {
            options.requireOnly("classpath", "assumeStandardRuntime", "assumeClosedWorld");
            return new ReflectionTransformer(options.strings("classpath"), options.bool("assumeStandardRuntime"), options.bool("assumeClosedWorld"));
        }
    }

    static int cleanScaffolding(MethodContext context) {
        int total = 0;
        while (true) {
            CodeGraph g = context.graph(); RegisterLiveness live = new RegisterLiveness(g); BitSet remove = new BitSet();
            for (int i = 0; i < g.size(); i++) {
                Instruction insn = g.at(i);
                if (insn.getOpcode() != Opcode.INVOKE_STATIC && insn.getOpcode() != Opcode.INVOKE_STATIC_RANGE) continue;
                var method = ReflectionModel.methodRef(insn);
                if (!method.getName().equals("valueOf") || method.getParameterTypes().size() != 1) continue;
                String type = method.getParameterTypes().get(0).toString();
                if (ReflectionCode.reference(type) || !ReflectionCode.box(type).equals(method.getDefiningClass()) || !method.getReturnType().equals(method.getDefiningClass())) continue;
                if (i + 1 < g.size() && g.at(i + 1).getOpcode() == Opcode.MOVE_RESULT_OBJECT) {
                    if (!live.deadAfter(i + 1, g.at(i + 1))) continue;
                    remove.set(i + 1);
                }
                remove.set(i);
            }
            ExceptionEdits.remove(context, remove); int changed = remove.cardinality() + DeadAssignments.remove(context);
            total += changed; if (changed == 0) return total;
        }
    }

    static int cleanStrings(MethodContext context, Map<String, Boolean> helpers) { return cleanStrings(context, helpers, Set.of()); }
    static int cleanStrings(MethodContext context, Map<String, Boolean> helpers, Set<String> contentFields) {
        if (helpers.isEmpty()) return 0;
        CodeGraph g = context.graph(); ConstantAnalysis constants = new ConstantAnalysis(g, ConstantEvaluator::step, false, true);
        ReflectionTypes types = new ReflectionTypes(context.original(), g);
        List<Edits.Edit> edits = new ArrayList<>(); List<BuilderInstruction> deleted = new ArrayList<>(); int count = 0;
        for (int i = 0; i + 1 < g.size(); i++) {
            Instruction call = g.at(i);
            if (call.getOpcode() != Opcode.INVOKE_STATIC && call.getOpcode() != Opcode.INVOKE_STATIC_RANGE) continue;
            Boolean interned = helpers.get(Signatures.of(ReflectionModel.methodRef(call))); if (interned == null) continue;
            int[] args = ConstantEvaluator.arguments(call); Constants state = constants.before(i);
            if (args.length != 2 || state == null || !(state.get(args[1]) instanceof String text)
                    || g.at(i + 1).getOpcode() != Opcode.MOVE_RESULT_OBJECT || g.leaders().contains(i + 1)) continue;
            if (!interned && !StringContentUses.onlyContent(g, types, i + 1, contentFields)) continue;
            int dest = ((OneRegisterInstruction)g.at(i + 1)).getRegisterA();
            edits.add(new Edits.Edit(i, false, List.of(Edits.constant(dest, text))));
            var nop = new BuilderInstruction10x(Opcode.NOP); deleted.add(nop); edits.add(new Edits.Edit(i + 1, false, List.of(nop))); count++;
            if (i + 2 < g.size() && g.at(i + 2).getOpcode() == Opcode.CHECK_CAST && !g.leaders().contains(i + 2)
                    && ((OneRegisterInstruction)g.at(i + 2)).getRegisterA() == dest
                    && ((TypeReference)((ReferenceInstruction)g.at(i + 2)).getReference()).getType().equals(ReflectionModel.STRING)) {
                var cast = new BuilderInstruction10x(Opcode.NOP); deleted.add(cast); edits.add(new Edits.Edit(i + 2, false, List.of(cast)));
            }
        }
        Edits.apply(context.code(), edits); BitSet remove = new BitSet();
        for (var nop : deleted) remove.set(nop.getLocation().getIndex()); ExceptionEdits.remove(context, remove);
        return count;
    }
}
