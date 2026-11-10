package me.naptila.deobfuscator.transformers.np.controlflow;

import java.util.*;

import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.transformers.np.NpTransformer;
import me.naptila.deobfuscator.transformers.np.analysis.NpHelpers;

import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.instruction.BuilderInstruction10x;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.MethodReference;

/** Expose known helper results without removing calls; fold proven integer branches. */
public final class OpaquePredicateTransformer extends NpTransformer {
    public String id() { return "np.opaque-predicates"; }
    public PassResult run(MethodContext context) {
        CodeGraph graph = context.graph();
        if (!applies(context, graph)) return PassResult.unchanged();
        ConstantAnalysis facts = model.analyze(graph);
        List<Edits.Edit> edits = new ArrayList<>();
        for (int i = 0; i < graph.size(); i++) {
            Constants state = facts.before(i); if (state == null) continue;
            Instruction insn = graph.at(i);
            Boolean decision = ConstantBranches.decision(insn, state);
            if (decision != null) {
                edits.add(new Edits.Edit(i, false, List.of(decision ? Edits.jump(context.code(), graph.successors(i).get(0))
                        : new BuilderInstruction10x(Opcode.NOP))));
            } else if (i + 1 < graph.size() && (insn.getOpcode() == Opcode.INVOKE_STATIC || insn.getOpcode() == Opcode.INVOKE_STATIC_RANGE)
                    && insn instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference m
                    && (model.helpers().hashes().contains(Signatures.of(m)) || model.helpers().guards().containsKey(Signatures.of(m)))
                    && graph.at(i + 1).getOpcode() == Opcode.MOVE_RESULT && !graph.leaders().contains(i + 1)) {
                model.step(insn, state);
                if (state.result() instanceof Integer n)
                    edits.add(new Edits.Edit(i + 1, false, List.of(Edits.constant(NpHelpers.reg(graph.at(i + 1)), n))));
            }
        }
        Edits.apply(context.code(), edits);
        return PassResult.changed(edits.size());
    }

    public static final class Provider extends NpTransformer.Provider {
        public String id() { return "np.opaque-predicates"; }
        public String displayName() { return "Opaque predicates"; }
        public String description() { return "Evaluate verified helpers and simplify proven conditions."; }
        public DexPass create(TransformerOptions options) {
            options.requireOnly();
            return new OpaquePredicateTransformer();
        }
    }
}
