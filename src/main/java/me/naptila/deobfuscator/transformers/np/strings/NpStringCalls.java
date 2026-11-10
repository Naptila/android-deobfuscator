package me.naptila.deobfuscator.transformers.np.strings;

import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.transformers.np.analysis.NpModel;
import me.naptila.deobfuscator.transformers.np.analysis.NpArrays;
import me.naptila.deobfuscator.transformers.np.support.ProxyAccess;

import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import me.naptila.deobfuscator.dex.*;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.MethodReference;

/** Shared proof for decoding and eliminating a call; never execute target code. */
public final class NpStringCalls {
    private NpStringCalls() {}
    private final Map<String, Boolean> harmlessInitializers = new HashMap<>();

    /** Empty initializers and private short tables have no business effects. */
    public static boolean initializationSafe(DexContext dex, String owner, String caller) {
        if (ProxyAccess.initializationSafe(dex, owner, caller)) return true;
        return dex.analysis(NpStringCalls.class, unused -> new NpStringCalls()).harmlessInitializers.computeIfAbsent(owner, key -> {
            var cls = dex.classes().get(key);
            if (cls == null || !"Ljava/lang/Object;".equals(cls.getSuperclass()) || !cls.getInterfaces().isEmpty()) return false;
            var initializer = dex.methods().get(key + "-><clinit>()V");
            if (initializer == null || initializer.getImplementation() == null || !initializer.getImplementation().getTryBlocks().isEmpty()) return false;
            var graph = new CodeGraph(initializer.getImplementation());
            int operations = 0; boolean empty = true;
            for (int i = 0; i < graph.size(); i++) if (graph.at(i).getOpcode() != Opcode.NOP) {
                operations++; empty &= graph.at(i).getOpcode() == Opcode.RETURN_VOID;
            }
            if (empty && operations == 1) return true;
            var table = NpArrays.Initializer.find(graph);
            if (table == null || !table.pure()) return false;
            var field = dex.fields().get(table.field());
            return field != null && field.getDefiningClass().equals(key)
                    && org.jf.dexlib2.AccessFlags.PRIVATE.isSet(field.getAccessFlags())
                    && org.jf.dexlib2.AccessFlags.STATIC.isSet(field.getAccessFlags())
                    && org.jf.dexlib2.AccessFlags.FINAL.isSet(field.getAccessFlags());
        });
    }
    public record Slice(List<Short> data, int start, int count, int key) {
        public String decode() {
            char[] text = new char[count];
            for (int j = 0; j < count; j++) text[j] = (char)(data.get(start + j) ^ key);
            return new String(text);
        }
    }
    public static boolean isDecoder(NpModel model, Instruction instruction) {
        return (instruction.getOpcode() == Opcode.INVOKE_STATIC || instruction.getOpcode() == Opcode.INVOKE_STATIC_RANGE)
                && instruction instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference method
                && model.helpers().decoders().contains(Signatures.of(method));
    }
    public static boolean isConstantGetter(NpModel model, Instruction instruction) {
        return (instruction.getOpcode() == Opcode.INVOKE_STATIC || instruction.getOpcode() == Opcode.INVOKE_STATIC_RANGE)
                && instruction instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference method
                && model.stringGetters().containsKey(Signatures.of(method));
    }
    public static boolean isProxy(NpModel model, Instruction instruction) {
        return (instruction.getOpcode() == Opcode.INVOKE_STATIC || instruction.getOpcode() == Opcode.INVOKE_STATIC_RANGE)
                && instruction instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference method
                && model.stringProxies().containsKey(Signatures.of(method));
    }
    public static String value(NpModel model, Instruction instruction, Constants state) {
        if (state == null || !isDecoder(model, instruction) && !isConstantGetter(model, instruction) && !isProxy(model, instruction)) return null;
        return value(model, instruction, state, new HashSet<>(), new int[]{4096});
    }
    private static String value(NpModel model, Instruction instruction, Constants state, Set<String> active, int[] budget) {
        if (state == null) return null;
        Slice slice = resolve(model, instruction, state);
        if (slice != null) return slice.decode();
        if (isConstantGetter(model, instruction))
            return model.stringGetters().get(Signatures.of((MethodReference) ((ReferenceInstruction) instruction).getReference()));
        if (!isProxy(model, instruction)) return null;
        String signature = Signatures.of((MethodReference) ((ReferenceInstruction) instruction).getReference());
        if (active.size() >= 8 || !active.add(signature)) return null;
        try {
            var method = model.stringProxies().get(signature);
            var code = method.getImplementation();
            int[] args = ConstantEvaluator.arguments(instruction);
            if (args.length != method.getParameterTypes().size()) return null;
            Constants local = new Constants();
            for (int n = 0; n < args.length; n++) local.put(code.getRegisterCount() - args.length + n, state.get(args[n]));
            for (Instruction step : code.getInstructions()) {
                if (--budget[0] < 0) return null;
                if (step.getOpcode() == Opcode.RETURN_OBJECT)
                    return local.get(((org.jf.dexlib2.iface.instruction.OneRegisterInstruction) step).getRegisterA()) instanceof String s ? s : null;
                String nested = value(model, step, local, active, budget);
                model.step(step, local);
                if (nested != null) local.result(nested);
            }
            return null;
        } finally {
            active.remove(signature);
        }
    }
    public static Slice resolve(NpModel model, Instruction instruction, Constants state) {
        if (state == null || !isDecoder(model, instruction)) return null;
        int[] args = ConstantEvaluator.arguments(instruction);
        if (args.length != 4 || !(state.get(args[0]) instanceof Constants.FieldValue field)
                || !(state.get(args[1]) instanceof Integer start) || !(state.get(args[2]) instanceof Integer count)
                || !(state.get(args[3]) instanceof Integer key)) return null;
        List<Short> data = model.arrays().get(field.signature());
        if (data == null || start < 0 || count < 0 || (long)start + count > data.size()) return null;
        return new Slice(data, start, count, key);
    }
    public static boolean removable(NpModel model, Instruction instruction, Constants state) {
        return isDecoder(model, instruction)
                && model.helpers().removableDecoders().contains(Signatures.of((MethodReference)((ReferenceInstruction)instruction).getReference()))
                && resolve(model, instruction, state) != null;
    }
}
