package me.naptila.deobfuscator.transformers.cleanup;

import me.naptila.deobfuscator.dex.*;

import java.util.*;
import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.transform.TransformerProvider;
import org.jf.dexlib2.iface.instruction.OneRegisterInstruction;

/** Fold proven constant switches, retaining all computation before the switch. */
public final class ConstantSwitchTransformer implements DexPass {
    @Override public String id() { return "dex.constant-switch"; }
    @Override public PassResult run(MethodContext context) {
        boolean hasSwitch = false;
        for (var instruction : context.code().getInstructions()) if (CodeGraph.isSwitch(instruction.getOpcode())) { hasSwitch = true; break; }
        if (!hasSwitch) return PassResult.unchanged();
        CodeGraph graph = context.graph(); ConstantAnalysis analysis = new ConstantAnalysis(graph);
        List<Edits.Edit> edits = new ArrayList<>();
        for (int i = 0; i < graph.size(); i++) {
            if (!CodeGraph.isSwitch(graph.at(i).getOpcode())) continue;
            Constants state = analysis.before(i);
            if (state == null) continue;
            Object key = state.get(((OneRegisterInstruction) graph.at(i)).getRegisterA());
            if (key instanceof Integer n) {
                int target = graph.switchTarget(i, n);
                if (target != i) edits.add(new Edits.Edit(i, false, List.of(Edits.jump(context.code(), target))));
            }
        }
        Edits.apply(context.code(), edits);
        return PassResult.changed(edits.size());
    }

    public static final class Provider implements TransformerProvider {
        public String id() { return "dex.constant-switch"; }
        public String description() { return "Fold switches with proven constant selectors"; }
        public DexPass create(TransformerOptions options) {
            options.requireOnly();
            return new ConstantSwitchTransformer();
        }
    }
}
