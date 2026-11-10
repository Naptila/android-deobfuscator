package me.naptila.deobfuscator.transformers.np.reflection;

import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.transformers.np.analysis.NpHelpers;

import java.nio.charset.StandardCharsets;
import java.util.*;
import me.naptila.deobfuscator.dex.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;
import org.jf.dexlib2.immutable.reference.*;

/** Offline NP cache-dispatch schema reader. No execution, class loading or sample-name tables. */
final class ReflectionModel {
    static final String OBJECT = "Ljava/lang/Object;", STRING = "Ljava/lang/String;";
    record Target(Reference member, String text, boolean interned) {}
    record Entry(Method dispatcher, int id, Target target, MethodReference get, MethodReference put, MethodReference tail) {}
    final Map<String, Map<Integer, Entry>> dispatchers;
    final Set<String> cacheMethods = new HashSet<>();
    private final DexContext dex;
    private final MemberResolver resolver;
    private static final class Text { String value; }
    ReflectionModel(DexContext dex) {
        this.dex = dex; resolver = new MemberResolver(dex, new LibraryTypes(List.of()));
        Map<String, Map<Integer, Entry>> candidates = new HashMap<>();
        for (Method method : dex.methods().values()) {
            Map<Integer, Entry> entries = read(method);
            if (!entries.isEmpty()) candidates.put(Signatures.of(method), entries);
        }
        // Cache mutation outside the validated dispatch/get/put methods invalidates that owner.
        Set<String> invalid = new HashSet<>();
        Set<String> allowed = new HashSet<>(candidates.keySet()); allowed.addAll(cacheMethods);
        Map<String, String> cacheFields = new HashMap<>();
        for (var entries : candidates.values()) for (Entry entry : entries.values()) {
            FieldReference field = cacheField(entry.get());
            cacheFields.put(Signatures.of(field), field.getDefiningClass());
            if (!pureCacheInitializer(field.getDefiningClass())) invalid.add(field.getDefiningClass());
        }
        for (Method method : dex.methods().values()) if (method.getImplementation() != null)
            for (Instruction i : method.getImplementation().getInstructions()) if (i instanceof ReferenceInstruction r && r.getReference() instanceof FieldReference f
                    && cacheFields.containsKey(Signatures.of(f)) && !cacheMethods.contains(Signatures.of(method))
                    && !(method.getName().equals("<clinit>") && method.getDefiningClass().equals(f.getDefiningClass()))) invalid.add(f.getDefiningClass());
        for (Method method : dex.methods().values()) if (method.getImplementation() != null && !allowed.contains(Signatures.of(method)))
            for (Instruction i : method.getImplementation().getInstructions()) if (i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m
                    && cacheMethods.contains(Signatures.of(m))) invalid.add(m.getDefiningClass());
        candidates.entrySet().removeIf(e -> invalid.contains(e.getValue().values().iterator().next().dispatcher().getDefiningClass()));
        dispatchers = Map.copyOf(candidates);
    }
    private Map<Integer, Entry> read(Method method) {
        if (method.getImplementation() == null || !AccessFlags.STATIC.isSet(method.getAccessFlags()) || !AccessFlags.PUBLIC.isSet(method.getAccessFlags())
                || !method.getReturnType().equals(OBJECT) || !method.getImplementation().getTryBlocks().isEmpty()) return Map.of();
        List<? extends CharSequence> params = method.getParameterTypes();
        if (!params.equals(List.of("I")) && !params.equals(List.of("I", OBJECT)) && !params.equals(List.of("I", OBJECT, "[Ljava/lang/Object;"))) return Map.of();
        try {
            CodeGraph g = new CodeGraph(method.getImplementation());
            int base = g.at(0).getOpcode() == Opcode.CONST_4 && ((NarrowLiteralInstruction)g.at(0)).getNarrowLiteral() == 0 ? 1 : 0;
            int parameter = g.registers() - params.size();
            if (base == 1 && NpHelpers.reg(g.at(0)) >= parameter) return Map.of();
            if (g.size() < base + 11 || g.at(base + 0).getOpcode() != Opcode.INVOKE_STATIC || g.at(base + 1).getOpcode() != Opcode.MOVE_RESULT_OBJECT
                    || g.at(base + 2).getOpcode() != Opcode.IF_NEZ || !(g.at(base + 3) instanceof NarrowLiteralInstruction mask)
                    || g.at(base + 4).getOpcode() != Opcode.XOR_INT_2ADDR || !CodeGraph.isSwitch(g.at(base + 5).getOpcode())) return Map.of();
            MethodReference get = methodRef(g.at(base + 0));
            if (!Arrays.equals(ConstantEvaluator.arguments(g.at(base + 0)), new int[]{parameter}) || !cache(get, false)) return Map.of();
            int object = NpHelpers.reg(g.at(base + 1)), key = NpHelpers.reg(g.at(base + 3));
            if (NpHelpers.reg(g.at(base + 2)) != object || !Arrays.equals(NpHelpers.registers(g.at(base + 4)), new int[]{key, parameter}) || NpHelpers.reg(g.at(base + 5)) != key) return Map.of();
            MethodReference put = methodRef(g.at(base + 6)), tail = methodRef(g.at(base + 7));
            if (g.at(base + 6).getOpcode() != Opcode.INVOKE_STATIC || !cache(put, true) || !get.getName().equals(put.getName())
                    || !get.getDefiningClass().equals(method.getDefiningClass()) || !put.getDefiningClass().equals(method.getDefiningClass())
                    || !Arrays.equals(ConstantEvaluator.arguments(g.at(base + 6)), new int[]{parameter, object})
                    || !Signatures.of(cacheField(get)).equals(Signatures.of(cacheField(put)))
                    || g.successors(base + 2).get(0) != base + 7 || g.at(base + 7).getOpcode() != Opcode.INVOKE_STATIC
                    || g.at(base + 8).getOpcode() != Opcode.MOVE_RESULT_OBJECT || g.at(base + 9).getOpcode() != Opcode.RETURN_OBJECT
                    || NpHelpers.reg(g.at(base + 8)) != NpHelpers.reg(g.at(base + 9))) return Map.of();
            int[] expectedTail = new int[params.size()]; expectedTail[0] = object;
            for (int n = 1; n < params.size(); n++) expectedTail[n] = parameter + n;
            if (!Arrays.equals(ConstantEvaluator.arguments(g.at(base + 7)), expectedTail) || !tail.getReturnType().equals(OBJECT) || resolver.resolve(tail) == null) return Map.of();
            BitSet covered = new BitSet(); covered.set(0, base + 10);
            Map<Integer, Entry> entries = new LinkedHashMap<>();
            for (SwitchElement element : g.payload(base + 5).getSwitchElements()) {
                Target target = interpret(g, g.index(g.address(base + 5) + element.getOffset()), base + 6, object, covered, base);
                int id = element.getKey() ^ mask.getNarrowLiteral();
                if (target == null || entries.put(id, new Entry(method, id, target, get, put, tail)) != null) return Map.of();
                if (params.size() == 3 && !(target.member() instanceof MethodReference)) return Map.of();
                if (params.size() < 3 && target.member() instanceof MethodReference) return Map.of();
            }
            for (int i = 0; i < g.size(); i++) if (!covered.get(i) && !g.isPayload(i) && g.at(i).getOpcode() != Opcode.NOP) return Map.of();
            cacheMethods.add(Signatures.of(get)); cacheMethods.add(Signatures.of(put));
            return Map.copyOf(entries);
        } catch (IllegalArgumentException | ClassCastException | IndexOutOfBoundsException | NullPointerException error) { return Map.of(); }
    }
    private FieldReference cacheField(MethodReference ref) {
        Method method = dex.methods().get(Signatures.of(ref));
        return (FieldReference)((ReferenceInstruction)method.getImplementation().getInstructions().iterator().next()).getReference();
    }
    private boolean pureCacheInitializer(String owner) {
        Method init = dex.methods().get(owner + "-><clinit>()V");
        if (init == null || init.getImplementation() == null || !init.getImplementation().getTryBlocks().isEmpty()) return false;
        CodeGraph g = new CodeGraph(init.getImplementation());
        if (g.size() < 4 || g.size() % 3 != 1 || g.at(g.size() - 1).getOpcode() != Opcode.RETURN_VOID) return false;
        Set<String> initialized = new HashSet<>();
        for (int i = 0; i < g.size() - 1; i += 3) {
            if (g.at(i).getOpcode() != Opcode.NEW_INSTANCE || !((TypeReference)((ReferenceInstruction)g.at(i)).getReference()).getType().equals("Ljava/util/HashMap;")
                    || g.at(i + 1).getOpcode() != Opcode.INVOKE_DIRECT || !Signatures.of(methodRef(g.at(i + 1))).equals("Ljava/util/HashMap;-><init>()V")
                    || !Arrays.equals(ConstantEvaluator.arguments(g.at(i + 1)), new int[]{NpHelpers.reg(g.at(i))})
                    || g.at(i + 2).getOpcode() != Opcode.SPUT_OBJECT || NpHelpers.reg(g.at(i + 2)) != NpHelpers.reg(g.at(i))) return false;
            FieldReference field = (FieldReference)((ReferenceInstruction)g.at(i + 2)).getReference();
            if (!field.getDefiningClass().equals(owner) || !field.getType().equals("Ljava/util/Map;") || !initialized.add(Signatures.of(field))) return false;
        }
        for (Field f : dex.classes().get(owner).getFields()) if (f.getType().equals("Ljava/util/Map;") && !initialized.contains(Signatures.of(f))) return false;
        return true;
    }
    private boolean cache(MethodReference ref, boolean write) {
        Method m = dex.methods().get(Signatures.of(ref)); if (m == null || m.getImplementation() == null) return false;
        if (!AccessFlags.PUBLIC.isSet(m.getAccessFlags()) || !AccessFlags.STATIC.isSet(m.getAccessFlags()) || !m.getImplementation().getTryBlocks().isEmpty()) return false;
        CodeGraph g = new CodeGraph(m.getImplementation());
        if (g.size() != (write ? 5 : 6) || g.at(0).getOpcode() != Opcode.SGET_OBJECT) return false;
        FieldReference field = (FieldReference)((ReferenceInstruction)g.at(0)).getReference();
        Field f = dex.fields().get(Signatures.of(field));
        if (f == null || !f.getType().equals("Ljava/util/Map;") || !AccessFlags.PRIVATE.isSet(f.getAccessFlags()) || !AccessFlags.STATIC.isSet(f.getAccessFlags())) return false;
        int first = g.registers() - (write ? 2 : 1), map = NpHelpers.reg(g.at(0));
        if (!Signatures.of(methodRef(g.at(1))).equals("Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;")
                || !Arrays.equals(ConstantEvaluator.arguments(g.at(1)), new int[]{first}) || g.at(2).getOpcode() != Opcode.MOVE_RESULT_OBJECT) return false;
        int boxed = NpHelpers.reg(g.at(2));
        if (!Signatures.of(methodRef(g.at(3))).equals(write ? "Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;" : "Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;")) return false;
        if (!Arrays.equals(ConstantEvaluator.arguments(g.at(3)), write ? new int[]{map, boxed, first + 1} : new int[]{map, boxed})) return false;
        return write ? g.at(4).getOpcode() == Opcode.RETURN_VOID : g.at(4).getOpcode() == Opcode.MOVE_RESULT_OBJECT && g.at(5).getOpcode() == Opcode.RETURN_OBJECT && NpHelpers.reg(g.at(4)) == NpHelpers.reg(g.at(5));
    }
    private Target interpret(CodeGraph g, int pc, int stop, int object, BitSet covered, int base) {
        Object[] values = new Object[g.registers()]; Object pending = null;
        if (base == 1) values[NpHelpers.reg(g.at(0))] = 0;
        Set<Integer> seen = new HashSet<>();
        while (pc != stop && seen.add(pc)) {
            if (seen.size() > 20000) return null;
            covered.set(pc); Instruction i = g.at(pc); Opcode op = i.getOpcode(); int a = i instanceof OneRegisterInstruction one ? one.getRegisterA() : -1;
            if (CodeGraph.isGoto(op)) { pc = g.successors(pc).get(0); continue; }
            switch (op) {
                case NOP -> {}
                case CONST, CONST_4, CONST_16, CONST_HIGH16 -> values[a] = ((NarrowLiteralInstruction)i).getNarrowLiteral();
                case CONST_STRING, CONST_STRING_JUMBO -> values[a] = ((StringReference)((ReferenceInstruction)i).getReference()).getString();
                case MOVE_OBJECT, MOVE_OBJECT_FROM16, MOVE_OBJECT_16 -> values[a] = values[((TwoRegisterInstruction)i).getRegisterB()];
                case MOVE_RESULT_OBJECT -> { values[a] = pending; pending = null; }
                case INT_TO_BYTE -> values[a] = (int)(byte)(int)(Integer)values[((TwoRegisterInstruction)i).getRegisterB()];
                case NEW_ARRAY -> {
                    String type = ((TypeReference)((ReferenceInstruction)i).getReference()).getType();
                    int length = (Integer)values[((TwoRegisterInstruction)i).getRegisterB()];
                    if (length < 0 || length > 100000 || (!type.equals("[B") && !type.equals("[Ljava/lang/String;"))) return null;
                    values[a] = type.equals("[B") ? new byte[length] : new Object[length];
                }
                case APUT_BYTE, APUT_OBJECT -> {
                    var regs = (ThreeRegisterInstruction)i; int index = (Integer)values[regs.getRegisterC()];
                    if (op == Opcode.APUT_BYTE) ((byte[])values[regs.getRegisterB()])[index] = ((Integer)values[a]).byteValue();
                    else ((Object[])values[regs.getRegisterB()])[index] = values[a];
                }
                case NEW_INSTANCE -> {
                    if (!((TypeReference)((ReferenceInstruction)i).getReference()).getType().equals(STRING)) return null;
                    values[a] = new Text();
                }
                case INVOKE_DIRECT, INVOKE_DIRECT_RANGE, INVOKE_STATIC, INVOKE_STATIC_RANGE -> {
                    MethodReference call = methodRef(i); int[] args = ConstantEvaluator.arguments(i);
                    if (Signatures.of(call).equals("Ljava/lang/String;-><init>([B)V") && (op == Opcode.INVOKE_DIRECT || op == Opcode.INVOKE_DIRECT_RANGE))
                        ((Text)values[args[0]]).value = new String((byte[])values[args[1]], StandardCharsets.UTF_8);
                    else if (resolver.resolve(call) != null && call.getReturnType().equals(OBJECT) && call.getParameterTypes().equals(List.of(STRING, STRING, STRING)))
                        pending = new Target(new ImmutableFieldReference(type(text(values[args[0]])), text(values[args[1]]), type(text(values[args[2]]))), null, false);
                    else if (resolver.resolve(call) != null && call.getReturnType().equals(OBJECT) && call.getParameterTypes().equals(List.of(STRING, STRING, STRING, "[Ljava/lang/String;"))) {
                        List<String> parameters = (Objects.equals(values[args[3]], 0) ? java.util.stream.Stream.<Object>empty() : Arrays.stream((Object[])values[args[3]])).map(ReflectionModel::text).map(ReflectionModel::type).toList();
                        pending = new Target(new ImmutableMethodReference(type(text(values[args[0]])), text(values[args[1]]), parameters, type(text(values[args[2]]))), null, false);
                    } else return null;
                }
                default -> { return null; }
            }
            if (g.successors(pc).size() != 1) return null;
            pc = g.successors(pc).get(0);
        }
        if (pc != stop) return null;
        Object value = values[object];
        if (value instanceof Target target) return target;
        if (value instanceof String s) return new Target(null, s, true);
        if (value instanceof Text s && s.value != null) return new Target(null, s.value, false);
        return null;
    }
    static MethodReference methodRef(Instruction instruction) { return (MethodReference)((ReferenceInstruction)instruction).getReference(); }
    private static String text(Object value) { return value instanceof Text t ? t.value : (String)value; }
    static String type(String name) {
        return switch (name) {
            case "void" -> "V"; case "boolean" -> "Z"; case "byte" -> "B"; case "char" -> "C"; case "short" -> "S";
            case "int" -> "I"; case "long" -> "J"; case "float" -> "F"; case "double" -> "D";
            default -> name.startsWith("[") ? name.replace('.', '/') : "L" + name.replace('.', '/') + ";";
        };
    }
}
