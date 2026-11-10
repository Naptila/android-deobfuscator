package me.naptila.deobfuscator.transformers.strings;

import java.util.*;
import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.strings.StringDecoder;
import me.naptila.deobfuscator.strings.StringFogXorDecoder;
import me.naptila.deobfuscator.strings.XorStringDecoder;
import me.naptila.deobfuscator.transform.TransformerProvider;
import me.naptila.deobfuscator.transformers.np.analysis.NpAnalysis;
import me.naptila.deobfuscator.transformers.np.analysis.NpModel;
import me.naptila.deobfuscator.transformers.np.strings.NpStringCalls;
import me.naptila.deobfuscator.transformers.np.support.ProxyAccess;
import org.jf.dexlib2.AccessFlags;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.BuilderInstruction;
import org.jf.dexlib2.builder.instruction.BuilderInstruction32x;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.instruction.formats.ArrayPayload;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.reference.TypeReference;

/** Restore known results and remove explicitly configured pure calls with proven initialization. */
public final class StringDecryptTransformer implements DexPass {
    private final List<StringDecoder> decoders;
    private final Set<String> removableMethods;
    private Map<String, Method> wrappers = Map.of();
    private Map<String, Method> guards = Map.of();
    private final Map<String, CodeGraph> bodies = new HashMap<>();
    private final Set<String> harmlessDecryptors = new HashSet<>();
    private NpModel model;
    private DexContext dex;
    /** Value recovery and effect checks describe the same selected execution path. */
    private static final class CallProof {
        final Set<String> decryptors = new HashSet<>();
        final Set<String> owners = new HashSet<>();
        boolean pure = true;
    }
    public StringDecryptTransformer(List<? extends StringDecoder> decoders) { this(decoders, Set.of()); }
    /** Removal explicitly trusts the listed decryptors to have no per-call business effects. */
    public StringDecryptTransformer(List<? extends StringDecoder> decoders, Set<String> removableMethods) {
        this.decoders = List.copyOf(decoders); this.removableMethods = Set.copyOf(removableMethods);
    }
    @Override public String id() { return "strings.decrypt"; }
    @Override public void prepare(DexContext dex) {
        this.dex = dex;
        bodies.clear(); harmlessDecryptors.clear(); wrappers = Map.of(); guards = Map.of(); model = null;
        if (decoders.isEmpty()) return;
        Map<String, Method> candidates = new HashMap<>(), integerGuards = new HashMap<>();
        Map<String, Set<String>> callers = new HashMap<>();
        Set<String> frontier = new HashSet<>();
        for (Method method : dex.methods().values()) {
            if (!eligible(method)) continue;
            String sig = Signatures.of(method);
            if (method.getReturnType().equals("I") && method.getParameterTypes().isEmpty()) integerGuards.put(sig, method);
            if (!method.getReturnType().equals("Ljava/lang/String;")) continue;
            candidates.put(sig, method);
            for (Instruction insn : method.getImplementation().getInstructions()) {
                if (!isStaticCall(insn)) continue;
                String target = Signatures.of((MethodReference) ((ReferenceInstruction) insn).getReference());
                callers.computeIfAbsent(target, unused -> new HashSet<>()).add(sig);
                if (decoders.stream().anyMatch(d -> d.supports(target))) frontier.add(target);
            }
        }
        // Limit body evaluation to forwarding paths that can reach a configured decoder.
        Set<String> reachable = new HashSet<>();
        for (int depth = 0; depth < 8 && !frontier.isEmpty(); depth++) {
            Set<String> next = new HashSet<>();
            for (String target : frontier) for (String caller : callers.getOrDefault(target, Set.of()))
                if (reachable.add(caller)) next.add(caller);
            frontier = next;
        }
        candidates.keySet().retainAll(reachable);
        wrappers = Map.copyOf(candidates);
        if (!wrappers.isEmpty()) {
            guards = Map.copyOf(integerGuards);
            model = NpAnalysis.of(dex).model();
        }
        for (String signature : removableMethods)
            if (harmlessDependencies(signature)) harmlessDecryptors.add(signature);
    }

    // The removal option supplies the per-call purity assumption, not an
    // assumption about class initialization. Check the entire local dependency
    // closure, including constructors and instance calls. Never run target code.
    private boolean harmlessDependencies(String root) {
        Set<String> initialized = new HashSet<>(), visiting = new HashSet<>(), methods = new HashSet<>();
        ArrayDeque<String> pending = new ArrayDeque<>(); pending.add(root);
        int budget = 8192;
        while (!pending.isEmpty()) {
            String signature = pending.removeFirst();
            if (!methods.add(signature)) continue;
            Method method = dex.methods().get(signature);
            if (method == null || method.getImplementation() == null || methods.size() > 64
                    || !harmlessInitialization(method.getDefiningClass(), initialized, visiting)) return false;
            if (model != null && (model.helpers().removableDecoders().contains(signature)
                    || model.helpers().removableHashes().contains(signature)
                    || model.helpers().removableGuards().contains(signature))) {
                var guard = model.helpers().guards().get(signature);
                if (guard != null && !harmlessInitialization(guard.field().substring(0, guard.field().indexOf("->")), initialized, visiting)) return false;
                continue;
            }
            CodeGraph graph = bodies.computeIfAbsent(signature, unused -> new CodeGraph(method.getImplementation()));
            for (int i = 0; i < graph.size(); i++) {
                if (--budget < 0) return false;
                Instruction insn = graph.at(i); Opcode op = insn.getOpcode();
                if (insn instanceof ReferenceInstruction ref && ref.getReference() instanceof MethodReference target) {
                    String callee = Signatures.of(target);
                    if (!dex.classes().containsKey(target.getDefiningClass()) && platformDependency(callee)) continue;
                    Method definition = dex.methods().get(callee);
                    if (definition == null || !ProxyAccess.visible(definition.getAccessFlags(), definition.getDefiningClass(), method.getDefiningClass())
                            || !ProxyAccess.type(dex, target.getDefiningClass(), method.getDefiningClass())
                            || AccessFlags.STATIC.isSet(definition.getAccessFlags()) != isStaticCall(insn)) return false;
                    if (op == Opcode.INVOKE_VIRTUAL || op == Opcode.INVOKE_VIRTUAL_RANGE) {
                        var owner = dex.classes().get(target.getDefiningClass());
                        int[] args = ConstantEvaluator.arguments(insn);
                        if (!AccessFlags.FINAL.isSet(definition.getAccessFlags()) && !AccessFlags.FINAL.isSet(owner.getAccessFlags())
                                && (args.length == 0 || !target.getDefiningClass().equals(allocatedReceiver(graph, i, args[0])))) return false;
                    } else if (op == Opcode.INVOKE_DIRECT || op == Opcode.INVOKE_DIRECT_RANGE) {
                        if (!target.getName().equals("<init>") && !AccessFlags.PRIVATE.isSet(definition.getAccessFlags())) return false;
                    } else if (!isStaticCall(insn)) return false;
                    pending.add(callee);
                } else if (op == Opcode.NEW_INSTANCE) {
                    String type = ((TypeReference) ((ReferenceInstruction) insn).getReference()).getType();
                    if (!ProxyAccess.type(dex, type, method.getDefiningClass()) || !harmlessInitialization(type, initialized, visiting)) return false;
                } else if (op.name.startsWith("sget") || op.name.startsWith("sput")) {
                    var field = (FieldReference) ((ReferenceInstruction) insn).getReference();
                    if (!dex.classes().containsKey(field.getDefiningClass())
                            && Signatures.of(field).equals("Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;")) continue;
                    var definition = dex.fields().get(Signatures.of(field));
                    if (definition == null || !AccessFlags.STATIC.isSet(definition.getAccessFlags())
                            || !ProxyAccess.visible(definition.getAccessFlags(), definition.getDefiningClass(), method.getDefiningClass())
                            || !ProxyAccess.type(dex, field.getDefiningClass(), method.getDefiningClass())
                            || !harmlessInitialization(field.getDefiningClass(), initialized, visiting)) return false;
                } else if (op.name.startsWith("invoke-")) return false;
            }
        }
        return true;
    }

    /** Only a fresh allocation in the same straight-line block proves exact dispatch. */
    private static String allocatedReceiver(CodeGraph graph, int call, int register) {
        if (graph.leaders().contains(call)) return null;
        for (int i = call - 1; i >= 0 && call - i <= 32; i--) {
            Instruction insn = graph.at(i); Opcode op = insn.getOpcode();
            if (RegisterLiveness.writes(insn).get(register)) {
                if (op == Opcode.NEW_INSTANCE) return ((TypeReference) ((ReferenceInstruction) insn).getReference()).getType();
                if (op == Opcode.MOVE_OBJECT || op == Opcode.MOVE_OBJECT_FROM16 || op == Opcode.MOVE_OBJECT_16)
                    register = ((TwoRegisterInstruction) insn).getRegisterB();
                else return null;
            }
            if (graph.leaders().contains(i)) break;
        }
        return null;
    }

    private static boolean platformDependency(String signature) {
        return Set.of("Ljava/lang/Object;-><init>()V", "Ljava/lang/String;->getBytes()[B",
                "Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B", "Ljava/lang/String;->getBytes(Ljava/lang/String;)[B",
                "Ljava/lang/String;->hashCode()I", "Ljava/lang/String;-><init>([C)V", "Ljava/lang/String;-><init>([B)V",
                "Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V", "Ljava/lang/String;-><init>([BLjava/lang/String;)V",
                "Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V",
                "Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V",
                "Landroid/util/Base64;->decode(Ljava/lang/String;I)[B").contains(signature);
    }

    private boolean harmlessInitialization(String owner, Set<String> initialized, Set<String> visiting) {
        if (initialized.contains(owner)) return true;
        if (!visiting.add(owner)) return false;
        try {
            ClassDef cls = dex.classes().get(owner);
            if (cls == null) return Set.of("Ljava/lang/Object;", "Ljava/lang/String;", "Ljava/lang/IllegalArgumentException;").contains(owner);
            if (NpStringCalls.initializationSafe(dex, owner, "")) { initialized.add(owner); return true; }
            if (!harmlessInitialization(cls.getSuperclass(), initialized, visiting)) return false;
            // Default interface methods can introduce additional initialization.
            // Abstract-only interfaces with no initializer cannot do so.
            for (String iface : cls.getInterfaces()) if (!abstractInterface(iface, new HashSet<>())) return false;
            Method initializer = dex.methods().get(owner + "-><clinit>()V");
            if (initializer != null && !privateInitializer(initializer, initialized, visiting)) return false;
            initialized.add(owner); return true;
        } finally { visiting.remove(owner); }
    }

    private boolean abstractInterface(String owner, Set<String> visiting) {
        var cls = dex.classes().get(owner);
        if (cls == null || !AccessFlags.INTERFACE.isSet(cls.getAccessFlags()) || !visiting.add(owner)) return false;
        try {
            for (Method method : cls.getMethods()) if (method.getName().equals("<clinit>")
                    || !AccessFlags.STATIC.isSet(method.getAccessFlags()) && !AccessFlags.ABSTRACT.isSet(method.getAccessFlags())) return false;
            for (String iface : cls.getInterfaces()) if (!abstractInterface(iface, visiting)) return false;
            return true;
        } finally { visiting.remove(owner); }
    }

    /** Private final primitive tables and stateless objects are the only accepted publications. */
    private boolean privateInitializer(Method method, Set<String> initialized, Set<String> visiting) {
        if (method.getImplementation() == null || !method.getImplementation().getTryBlocks().isEmpty()) return false;
        CodeGraph graph = new CodeGraph(method.getImplementation());
        if (graph.size() > 512) return false;
        Constants constants = new Constants();
        Map<Integer, String> types = new HashMap<>();
        Map<Integer, Integer> lengths = new HashMap<>();
        Set<Integer> constructed = new HashSet<>();
        for (int i = 0; i < graph.size(); i++) {
            Instruction insn = graph.at(i); Opcode op = insn.getOpcode();
            if (op == Opcode.RETURN_VOID) return true;
            if (op == Opcode.NOP) continue;
            if (op == Opcode.NEW_ARRAY) {
                var array = (TwoRegisterInstruction) insn;
                String type = ((TypeReference) ((ReferenceInstruction) insn).getReference()).getType();
                if (type.length() != 2 || "ZBCSIJFD".indexOf(type.charAt(1)) < 0
                        || !(constants.get(array.getRegisterB()) instanceof Integer length) || length < 0 || length > 1_000_000) return false;
                types.put(array.getRegisterA(), type); lengths.put(array.getRegisterA(), length); constructed.remove(array.getRegisterA());
            } else if (op == Opcode.FILL_ARRAY_DATA) {
                int register = ((OneRegisterInstruction) insn).getRegisterA();
                if (!lengths.containsKey(register) || !(graph.at(graph.payloadIndex(i)) instanceof ArrayPayload payload)
                        || payload.getArrayElements().size() > lengths.get(register)) return false;
                int width = switch (types.get(register)) { case "[Z", "[B" -> 1; case "[C", "[S" -> 2; case "[I", "[F" -> 4; default -> 8; };
                if (payload.getElementWidth() != width) return false;
            } else if (op == Opcode.NEW_INSTANCE) {
                int register = ((OneRegisterInstruction) insn).getRegisterA();
                String type = ((TypeReference) ((ReferenceInstruction) insn).getReference()).getType();
                var cls = dex.classes().get(type);
                if (cls == null || AccessFlags.ABSTRACT.isSet(cls.getAccessFlags()) || AccessFlags.INTERFACE.isSet(cls.getAccessFlags())
                        || !ProxyAccess.type(dex, type, method.getDefiningClass()) || !harmlessInitialization(type, initialized, visiting)) return false;
                types.put(register, type); lengths.remove(register); constructed.remove(register);
            } else if (op == Opcode.INVOKE_DIRECT || op == Opcode.INVOKE_DIRECT_RANGE) {
                var target = (MethodReference) ((ReferenceInstruction) insn).getReference();
                int[] args = ConstantEvaluator.arguments(insn);
                if (args.length != 1 || !target.getName().equals("<init>") || !target.getParameterTypes().isEmpty()
                        || !target.getDefiningClass().equals(types.get(args[0])) || constructed.contains(args[0])
                        || !emptyConstructor(target, method.getDefiningClass())) return false;
                constructed.add(args[0]);
            } else if (op == Opcode.SPUT_OBJECT) {
                var ref = (FieldReference) ((ReferenceInstruction) insn).getReference();
                var field = dex.fields().get(Signatures.of(ref));
                int register = ((OneRegisterInstruction) insn).getRegisterA();
                if (field == null || !field.getDefiningClass().equals(method.getDefiningClass())
                        || !AccessFlags.PRIVATE.isSet(field.getAccessFlags()) || !AccessFlags.STATIC.isSet(field.getAccessFlags())
                        || !AccessFlags.FINAL.isSet(field.getAccessFlags()) || AccessFlags.VOLATILE.isSet(field.getAccessFlags())
                        || !field.getType().equals(types.get(register))
                        || !lengths.containsKey(register) && !constructed.contains(register)) return false;
            } else if (op == Opcode.CONST_4 || op == Opcode.CONST_16 || op == Opcode.CONST || op == Opcode.CONST_HIGH16) {
                int register = ((OneRegisterInstruction) insn).getRegisterA();
                types.remove(register); lengths.remove(register); constructed.remove(register);
            } else return false;
            ConstantEvaluator.step(insn, constants);
        }
        return false;
    }

    private boolean emptyConstructor(MethodReference ref, String caller) {
        Method method = dex.methods().get(Signatures.of(ref));
        ClassDef cls = dex.classes().get(ref.getDefiningClass());
        if (method == null || cls == null || !"Ljava/lang/Object;".equals(cls.getSuperclass())
                || AccessFlags.STATIC.isSet(method.getAccessFlags())
                || !ProxyAccess.visible(method.getAccessFlags(), method.getDefiningClass(), caller)
                || !ProxyAccess.type(dex, cls.getType(), caller) || method.getImplementation() == null
                || !method.getImplementation().getTryBlocks().isEmpty()) return false;
        for (Method member : cls.getMethods()) if (member.getName().equals("finalize")) return false;
        CodeGraph graph = new CodeGraph(method.getImplementation()); int operations = 0;
        for (int i = 0; i < graph.size(); i++) {
            Instruction insn = graph.at(i);
            if (insn.getOpcode() == Opcode.NOP) continue;
            if (operations++ == 0) {
                if (insn.getOpcode() != Opcode.INVOKE_DIRECT && insn.getOpcode() != Opcode.INVOKE_DIRECT_RANGE) return false;
                int[] args = ConstantEvaluator.arguments(insn);
                if (!Signatures.of((MethodReference) ((ReferenceInstruction) insn).getReference()).equals("Ljava/lang/Object;-><init>()V")
                        || args.length != 1 || args[0] != graph.registers() - 1) return false;
            } else if (operations != 2 || insn.getOpcode() != Opcode.RETURN_VOID) return false;
        }
        return operations == 2;
    }

    private static boolean eligible(Method method) {
        int flags = method.getAccessFlags();
        if (method.getImplementation() == null || method.getName().startsWith("<")
                || !AccessFlags.STATIC.isSet(flags) || !AccessFlags.PUBLIC.isSet(flags)
                || AccessFlags.SYNCHRONIZED.isSet(flags) || AccessFlags.DECLARED_SYNCHRONIZED.isSet(flags)
                || !method.getImplementation().getTryBlocks().isEmpty()
                || method.getParameterTypes().stream().anyMatch(t -> t.toString().equals("J") || t.toString().equals("D"))) return false;
        int size = 0;
        for (Instruction ignored : method.getImplementation().getInstructions()) if (++size > 512) return false;
        return size > 0;
    }

    private static boolean isStaticCall(Instruction insn) {
        return insn.getOpcode() == Opcode.INVOKE_STATIC || insn.getOpcode() == Opcode.INVOKE_STATIC_RANGE;
    }

    private Object decode(String signature, List<Object> arguments, Set<String> active, int[] budget) {
        return decode(signature, arguments, active, budget, null, null);
    }

    private Object decode(String signature, List<Object> arguments, Set<String> active, int[] budget,
                          CallProof proof, String caller) {
        boolean configured = false;
        for (StringDecoder decoder : decoders) if (decoder.supports(signature)) {
            configured = true;
            Optional<String> result = decoder.decode(signature, Collections.unmodifiableList(arguments));
            if (result.isPresent()) {
                if (proof != null) {
                    Method definition = dex.methods().get(signature);
                    proof.pure &= removableMethods.contains(signature) && definition != null && eligible(definition)
                            && ProxyAccess.member(dex, definition, caller, false);
                    proof.decryptors.add(signature);
                }
                return result.get();
            }
        }
        if (configured) { if (proof != null) proof.pure = false; return null; }
        Method method = wrappers.get(signature);
        if (method == null) method = guards.get(signature);
        if (method == null || arguments.size() != method.getParameterTypes().size()
                || active.size() >= 8 || !active.add(signature)) {
            if (proof != null) proof.pure = false;
            return null;
        }
        try {
            Method original = method;
            if (proof != null) {
                proof.pure &= ProxyAccess.member(dex, method, caller, false);
                proof.owners.add(method.getDefiningClass());
            }
            CodeGraph graph = bodies.computeIfAbsent(signature, unused -> new CodeGraph(original.getImplementation()));
            Constants state = new Constants();
            int parameters = graph.registers() - arguments.size();
            for (int i = 0; i < arguments.size(); i++) state.put(parameters + i, arguments.get(i));
            // This proves a return value on the selected normal path. The actual
            // invocation still performs every effect, initialization and exception.
            int cursor = 0;
            while (budget[0]-- > 0 && cursor >= 0 && cursor < graph.size() && !graph.isPayload(cursor)) {
                Instruction insn = graph.at(cursor);
                Opcode op = insn.getOpcode();
                if (op == Opcode.RETURN_OBJECT || op == Opcode.RETURN) {
                    Object result = state.get(((OneRegisterInstruction) insn).getRegisterA());
                    if (result == null && proof != null) proof.pure = false;
                    return result;
                }
                if (CodeGraph.isIf(op) && ConstantBranches.decision(insn, state) == null
                        || CodeGraph.isSwitch(op) && !(state.get(((OneRegisterInstruction) insn).getRegisterA()) instanceof Integer)) {
                    if (proof != null) proof.pure = false;
                    return null;
                }
                if (!CodeGraph.isIf(op) && !CodeGraph.isSwitch(op) && !CodeGraph.isGoto(op)) {
                    String name = op.name;
                    if (!(name.startsWith("const") || name.startsWith("move") || name.contains("-int")
                            || name.startsWith("sget") || op == Opcode.CHECK_CAST || op == Opcode.NOP || isStaticCall(insn))) {
                        if (proof != null) proof.pure = false;
                        return null;
                    }
                    step(insn, state, active, budget, proof, method.getDefiningClass());
                }
                List<Integer> next = ConstantBranches.successors(graph, cursor, state);
                if (next.size() != 1) { if (proof != null) proof.pure = false; return null; }
                cursor = next.get(0);
            }
            if (proof != null) proof.pure = false;
            return null;
        } finally {
            active.remove(signature);
        }
    }

    private void step(Instruction insn, Constants state, Set<String> active, int[] budget) {
        step(insn, state, active, budget, null, null);
    }

    private void step(Instruction insn, Constants state, Set<String> active, int[] budget, CallProof proof, String caller) {
        Object value = null;
        if (isStaticCall(insn)) {
            MethodReference method = (MethodReference) ((ReferenceInstruction) insn).getReference();
            if (method.getParameterTypes().stream().noneMatch(t -> t.toString().equals("J") || t.toString().equals("D"))) {
                List<Object> args = new ArrayList<>();
                for (int register : ConstantEvaluator.arguments(insn)) args.add(state.get(register));
                String signature = Signatures.of(method);
                boolean helper = proof != null && model != null
                        && (model.helpers().removableHashes().contains(signature) && args.size() == 1 && args.get(0) instanceof String
                            || model.helpers().removableGuards().contains(signature) && args.isEmpty()
                                && model.fields().containsKey(model.helpers().guards().get(signature).field())
                            || NpStringCalls.removable(model, insn, state));
                if (helper) {
                    proof.pure &= ProxyAccess.member(dex, method, caller, false);
                    proof.owners.add(method.getDefiningClass());
                    if (model.helpers().guards().containsKey(signature)) {
                        String field = model.helpers().guards().get(signature).field();
                        proof.owners.add(field.substring(0, field.indexOf("->")));
                    }
                    value = NpStringCalls.value(model, insn, state);
                } else value = decode(signature, args, active, budget, proof, caller);
            } else if (proof != null) proof.pure = false;
        } else if (proof != null && insn.getOpcode().name.startsWith("sget")) {
            FieldReference field = (FieldReference) ((ReferenceInstruction) insn).getReference();
            String signature = Signatures.of(field);
            var definition = dex.fields().get(signature);
            proof.pure &= definition != null && AccessFlags.STATIC.isSet(definition.getAccessFlags())
                    && !AccessFlags.VOLATILE.isSet(definition.getAccessFlags())
                    && ProxyAccess.member(dex, field, caller, false)
                    && (insn.getOpcode() == Opcode.SGET && model != null && model.fields().containsKey(signature)
                        || insn.getOpcode() == Opcode.SGET_OBJECT && model != null && model.arrays().containsKey(signature));
            proof.owners.add(field.getDefiningClass());
        } else if (proof != null && insn.getOpcode() == Opcode.CHECK_CAST) {
            String type = ((TypeReference) ((ReferenceInstruction) insn).getReference()).getType();
            Object input = state.get(((OneRegisterInstruction) insn).getRegisterA());
            proof.pure &= input instanceof String && Set.of("Ljava/lang/String;", "Ljava/lang/Object;").contains(type)
                    || input instanceof Constants.FieldValue field && type.equals("[S") && model != null && model.arrays().containsKey(field.signature());
        } else if (proof != null && insn.getOpcode().canThrow()
                && insn.getOpcode() != Opcode.CONST_STRING && insn.getOpcode() != Opcode.CONST_STRING_JUMBO) {
            proof.pure = false;
        }
        if (model == null) ConstantEvaluator.step(insn, state);
        else model.step(insn, state);
        if (value != null) state.result(value);
    }

    /** Prove each incoming edge separately, preserving the correlation between arguments. */
    private Map<Integer, String> branchResults(CodeGraph graph, ConstantAnalysis analysis, int call,
                                               String signature, List<List<Integer>> predecessors, BitSet handlers) {
        int join = call;
        List<Integer> suffix = new ArrayList<>();
        Set<Integer> visited = new HashSet<>();
        while (visited.add(join) && suffix.size() < 32 && !handlers.get(join) && join != 0) {
            List<Integer> incoming = predecessors.get(join);
            if (incoming.size() >= 2) {
                if (incoming.size() > 8) return Map.of();
                Map<Integer, String> results = new LinkedHashMap<>();
                for (int edge : incoming) {
                    Constants before = analysis.before(edge);
                    if (before == null) continue;
                    if (handlers.get(edge) || !plainEdge(graph.at(edge)) || graph.successors(edge).size() != 1
                            || !graph.protection(edge).equals(graph.protection(call))) return Map.of();
                    Constants state = before.copy();
                    step(graph.at(edge), state, new HashSet<>(), new int[]{4096});
                    for (int i = suffix.size() - 1; i >= 0; i--)
                        step(graph.at(suffix.get(i)), state, new HashSet<>(), new int[]{4096});
                    List<Object> arguments = new ArrayList<>();
                    for (int register : ConstantEvaluator.arguments(graph.at(call))) arguments.add(state.get(register));
                    Object result = decode(signature, arguments, new HashSet<>(), new int[]{4096});
                    if (!(result instanceof String plain)) return Map.of();
                    results.put(edge, plain);
                }
                return results;
            }
            if (incoming.size() != 1) return Map.of();
            int previous = incoming.get(0);
            if (!plainEdge(graph.at(previous)) || graph.successors(previous).size() != 1
                    || !graph.protection(previous).equals(graph.protection(call))) return Map.of();
            suffix.add(previous);
            join = previous;
        }
        return Map.of();
    }

    private static boolean plainEdge(Instruction instruction) {
        Opcode op = instruction.getOpcode();
        return CodeGraph.isGoto(op) || op == Opcode.NOP || op == Opcode.CHECK_CAST
                || op.name.startsWith("const") || op.name.startsWith("move")
                && !op.name.startsWith("move-result") && op != Opcode.MOVE_EXCEPTION;
    }

    @Override public PassResult run(MethodContext context) {
        if (decoders.isEmpty()) return PassResult.unchanged();
        CodeGraph graph = context.graph();
        boolean relevant = false;
        for (int i = 0; i < graph.size(); i++) if (isStaticCall(graph.at(i))) {
            String sig = Signatures.of((MethodReference) ((ReferenceInstruction) graph.at(i)).getReference());
            if (wrappers.containsKey(sig) || decoders.stream().anyMatch(d -> d.supports(sig))) { relevant = true; break; }
        }
        if (!relevant) return PassResult.unchanged();
        ConstantAnalysis analysis = new ConstantAnalysis(graph, (i, state) -> step(i, state, new HashSet<>(), new int[]{4096}), false, true);
        List<Edits.Edit> edits = new ArrayList<>();
        Map<Integer, CallProof> decoded = new HashMap<>();
        BitSet restored = new BitSet();
        int proxies = 0, branches = 0, scratch = 0;
        List<List<Integer>> predecessors = null;
        BitSet handlers = new BitSet();
        Set<Integer> assignedEdges = new HashSet<>();
        for (int i = 0; i < graph.size(); i++) {
            Instruction insn = graph.at(i);
            if (insn.getOpcode() != Opcode.INVOKE_STATIC && insn.getOpcode() != Opcode.INVOKE_STATIC_RANGE) continue;
            MethodReference method = (MethodReference) ((ReferenceInstruction) insn).getReference();
            if (!method.getReturnType().equals("Ljava/lang/String;")) continue;
            // The first API version models single-register arguments only.
            if (method.getParameterTypes().stream().anyMatch(t -> t.toString().equals("J") || t.toString().equals("D"))) continue;
            Constants state = analysis.before(i); if (state == null) continue;
            String signature = Signatures.of(method);
            List<Object> arguments = new ArrayList<>();
            for (int register : ConstantEvaluator.arguments(insn)) arguments.add(state.get(register));
            CallProof proof = removableMethods.isEmpty() ? null : new CallProof();
            Object value = decode(signature, arguments, new HashSet<>(), new int[]{4096}, proof, context.original().getDefiningClass());
            if (value instanceof String && proof != null) decoded.put(i, proof);
            if (i + 1 == graph.size() || graph.at(i + 1).getOpcode() != Opcode.MOVE_RESULT_OBJECT || graph.leaders().contains(i + 1)) continue;
            if (value instanceof String result) {
                int register = ((OneRegisterInstruction) graph.at(i + 1)).getRegisterA();
                edits.add(new Edits.Edit(i + 1, false, List.of(Edits.constant(register, result))));
                restored.set(i);
                if (wrappers.containsKey(signature)) proxies++;
            } else if (graph.registers() + scratch < 256) {
                if (predecessors == null) {
                    predecessors = new ArrayList<>();
                    for (int index = 0; index < graph.size(); index++) predecessors.add(new ArrayList<>());
                    for (int index = 0; index < graph.size(); index++) {
                        for (int target : graph.successors(index)) predecessors.get(target).add(index);
                        for (CodeGraph.Handler handler : graph.protection(index)) handlers.set(handler.target());
                    }
                }
                Map<Integer, String> results = branchResults(graph, analysis, i, signature, predecessors, handlers);
                if (results.size() < 2 || results.keySet().stream().anyMatch(assignedEdges::contains)) continue;
                int register = ((OneRegisterInstruction) graph.at(i + 1)).getRegisterA();
                if (new HashSet<>(results.values()).size() == 1) {
                    edits.add(new Edits.Edit(i + 1, false, List.of(Edits.constant(register, results.values().iterator().next()))));
                } else {
                    int temporary = graph.registers() + scratch++;
                    for (var entry : results.entrySet()) {
                        int edge = entry.getKey();
                        BuilderInstruction original = CodeGraph.isGoto(graph.at(edge).getOpcode())
                                ? Edits.jump(context.code(), graph.successors(edge).get(0)) : Edits.copy(graph.at(edge), graph.registers());
                        List<BuilderInstruction> replacement = CodeGraph.isGoto(graph.at(edge).getOpcode())
                                ? List.of(Edits.constant(temporary, entry.getValue()), original)
                                : List.of(original, Edits.constant(temporary, entry.getValue()));
                        edits.add(new Edits.Edit(edge, false, replacement));
                    }
                    assignedEdges.addAll(results.keySet());
                    edits.add(new Edits.Edit(i + 1, false, List.of(new BuilderInstruction32x(Opcode.MOVE_OBJECT_16, register, temporary))));
                }
                branches++;
                if (wrappers.containsKey(signature)) proxies++;
            }
        }
        List<String> notes = new ArrayList<>();
        if (proxies > 0) notes.add("string decryptor proxy results restored (calls retained): " + proxies);
        if (branches > 0) notes.add("branch string results restored (calls retained): " + branches);
        BitSet remove = removableCalls(context, graph, decoded, restored, notes);
        List<BuilderInstruction> removedCalls = new ArrayList<>();
        for (int i = remove.nextSetBit(0); i >= 0; i = remove.nextSetBit(i + 1)) removedCalls.add(context.code().getInstructions().get(i));
        Edits.apply(context.code(), edits);
        // Result/edge restoration can insert instructions. Relocate the recorded
        // call identities instead of applying indices from the old snapshot.
        BitSet relocated = new BitSet();
        for (BuilderInstruction instruction : removedCalls) relocated.set(instruction.getLocation().getIndex());
        ExceptionEdits.remove(context, relocated);
        if (scratch > 0) context.appendScratchRegisters(scratch);
        int cleanup = remove.cardinality();
        if (cleanup > 0) cleanup += DeadAssignments.remove(context);
        return new PassResult(edits.size() + cleanup, notes);
    }

    private BitSet removableCalls(MethodContext context, CodeGraph graph, Map<Integer, CallProof> decoded, BitSet restored, List<String> notes) {
        Map<Integer, Set<String>> completed = new HashMap<>();
        Set<String> owners = new HashSet<>();
        decoded.forEach((site, proof) -> {
            if (proof.pure) { completed.put(site, proof.decryptors); owners.addAll(proof.owners); }
        });
        // A call with unknown arguments may normally return null before reaching
        // the actual decryptor or its dependencies. Only valid modeled inputs
        // establish successful decryption for later calls.
        var successful = ProxyAccess.successfulCallsBefore(context, graph, removableMethods, completed);
        var initialized = ProxyAccess.initializedBefore(context, graph, owners);
        BitSet remove = new BitSet(); int initialization = 0, effects = 0, proxies = 0, harmless = 0;
        for (var entry : decoded.entrySet()) {
            int i = entry.getKey(); CallProof proof = entry.getValue();
            if (!proof.pure) { effects++; continue; }
            if (!restored.get(i) && i + 1 < graph.size() && graph.at(i + 1).getOpcode() == Opcode.MOVE_RESULT_OBJECT) continue;
            // Harmless dependency initialization allows even the first valid
            // decryption to disappear. Otherwise require prior successful calls
            // on every path; exceptional edges retain their pre-call facts.
            boolean prior = proof.decryptors.stream().allMatch(sig -> successful.containsKey(sig) && successful.get(sig).get(i));
            boolean ready = proof.decryptors.stream().allMatch(sig -> harmlessDecryptors.contains(sig)
                        || successful.containsKey(sig) && successful.get(sig).get(i))
                    && proof.owners.stream().allMatch(owner -> NpStringCalls.initializationSafe(context.dex(), owner, context.original().getDefiningClass())
                        || initialized.containsKey(owner) && initialized.get(owner).get(i));
            if (!ready) { initialization++; continue; }
            remove.set(i);
            if (!prior) harmless++;
            String signature = Signatures.of((MethodReference) ((ReferenceInstruction) graph.at(i)).getReference());
            if (wrappers.containsKey(signature)) proxies++;
        }
        if (effects > 0) notes.add("decoded calls retained for unproven effects or access: " + effects);
        if (initialization > 0) notes.add("decrypt calls retained for first successful invocation: " + initialization);
        if (remove.isEmpty()) return remove;
        notes.add("decrypted calls removed: " + remove.cardinality());
        if (harmless > 0) notes.add("decrypted calls removed with proven harmless dependency initialization: " + harmless);
        if (proxies > 0) notes.add("proven decryptor proxy calls removed: " + proxies);
        notes.add("removeDecryptedCalls enabled: configured decryptors assumed free of per-call business effects; allocation and VM failures may differ");
        return remove;
    }

    public static final class Provider implements TransformerProvider {
        public String id() { return "strings.decrypt"; }
        public String displayName() { return "Custom string decryption"; }
        public String description() {
            return "Configure UTF-16 XOR or StringFog decryption by exact method signature. Unconfigured methods are preserved.";
        }
        public DexPass create(TransformerOptions options) {
            options.requireOnly("xorMethods", "stringFogXorMethods", "removeDecryptedCalls");
            List<StringDecoder> decoders = new ArrayList<>();
            ServiceLoader.load(StringDecoder.class).forEach(decoders::add);
            options.strings("xorMethods").forEach(signature -> decoders.add(new XorStringDecoder(signature)));
            options.strings("stringFogXorMethods").forEach(signature -> decoders.add(new StringFogXorDecoder(signature)));
            var removable = new HashSet<String>();
            if (options.bool("removeDecryptedCalls")) {
                removable.addAll(options.strings("xorMethods"));
                removable.addAll(options.strings("stringFogXorMethods"));
            }
            return new StringDecryptTransformer(decoders, removable);
        }
    }
}
