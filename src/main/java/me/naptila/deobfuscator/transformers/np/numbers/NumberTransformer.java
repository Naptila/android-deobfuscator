package me.naptila.deobfuscator.transformers.np.numbers;

import java.util.*;

import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.transformers.np.NpTransformer;
import me.naptila.deobfuscator.transformers.np.analysis.NpHelpers;

import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.instruction.BuilderInstruction51l;
import org.jf.dexlib2.iface.instruction.*;

/** Fold known int computations and NP wide XOR constants; retain reads and their effects. */
public final class NumberTransformer extends NpTransformer {
    private static final Set<Opcode> INTEGER_OPS = EnumSet.noneOf(Opcode.class);
    static {
        for (Opcode op : Opcode.values()) if (op.name.matches("(xor|and|or|add|sub|rsub|mul|div|rem|shl|shr|ushr|neg|not)-int.*")) INTEGER_OPS.add(op);
    }
    public String id() { return "np.numbers"; }
    public PassResult run(MethodContext context) {
        CodeGraph graph = context.graph();
        if (!applies(context, graph) && !applies(context, context.originalGraph()))
            return PassResult.unchanged();
        ConstantAnalysis facts = model.analyze(graph);
        WideConstantAnalysis wide = null;
        List<Edits.Edit> edits = new ArrayList<>();
        for (int i = 0; i < graph.size(); i++) {
            Instruction insn = graph.at(i);
            if (insn.getOpcode() == Opcode.INT_TO_LONG || insn.getOpcode() == Opcode.XOR_LONG || insn.getOpcode() == Opcode.XOR_LONG_2ADDR) {
                if (wide == null) wide = new WideConstantAnalysis(graph, facts);
                Long value = wide.valueAt(i); int dest = NpHelpers.reg(insn);
                if (dest <= 255 && value != null)
                    edits.add(new Edits.Edit(i, false, List.of(new BuilderInstruction51l(Opcode.CONST_WIDE, dest, value))));
                continue;
            }
            if (!INTEGER_OPS.contains(insn.getOpcode())) continue;
            Constants state = facts.before(i);
            if (state == null) continue;
            if (!ConstantEvaluator.step(insn, state)) continue;
            int dest = NpHelpers.reg(insn);
            if (dest <= 255 && state.get(dest) instanceof Integer n)
                edits.add(new Edits.Edit(i, false, List.of(Edits.constant(dest, n))));
        }
        Edits.apply(context.code(), edits);
        return PassResult.changed(edits.size());
    }

    public static final class Provider extends NpTransformer.Provider {
        public String id() { return "np.numbers"; }
        public String displayName() { return "Numeric constants"; }
        public String description() { return "Recover verified integer constants and wide XOR constants."; }
        public DexPass create(TransformerOptions options) {
            options.requireOnly();
            return new NumberTransformer();
        }
    }
}
