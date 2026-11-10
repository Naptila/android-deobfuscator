package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.immutable.ImmutableMethodImplementation;

/** Delete instructions while relocating try labels and dropping empty protection ranges. */
public final class ExceptionEdits {
    private ExceptionEdits() {}
    public static void remove(MethodContext context, BitSet remove) {
        if (remove.isEmpty()) return;
        CodeGraph graph = context.graph();
        var code = context.code();
        List<BuilderInstruction> snapshot = new ArrayList<>(code.getInstructions());
        List<BuilderTryBlock> retained = new ArrayList<>();
        for (BuilderTryBlock block : code.getTryBlocks()) {
            boolean useful = false;
            for (int i = 0; i < graph.size(); i++) {
                if (!remove.get(i) && graph.at(i).getOpcode().canThrow()
                        && graph.address(i) >= block.getStartCodeAddress()
                        && graph.address(i) < block.getStartCodeAddress() + block.getCodeUnitCount()) {
                    useful = true; break;
                }
            }
            if (useful) retained.add(block);
        }
        for (int i = remove.length() - 1; i >= 0; i = remove.previousSetBit(i - 1)) {
            code.removeInstruction(snapshot.get(i).getLocation().getIndex());
            if (i == 0) break;
        }
        // Builder try blocks follow their labels through deletion. Rebuild only to remove
        // obsolete entries; never change the handler types, ordering or live coverage.
        if (retained.size() != code.getTryBlocks().size())
            context.replaceCode(new ImmutableMethodImplementation(code.getRegisterCount(), code.getInstructions(), retained, code.getDebugItems()));
    }
}
