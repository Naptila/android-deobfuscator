package me.naptila.deobfuscator;

import java.util.*;
import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.dex.EngineProgress;
import me.naptila.deobfuscator.report.JsonReport;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.MethodImplementationBuilder;
import org.jf.dexlib2.builder.instruction.BuilderInstruction11x;
import org.junit.Test;
import static org.junit.Assert.*;

public class EngineProgressTest {
    @Test public void progressTracksActualMethodsRoundsAndFinalizersWithoutChangingResults() {
        var code = new MethodImplementationBuilder(1);
        Fixtures.integer(code, 0, 7);
        code.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        var dex = Fixtures.dex(Fixtures.method("first", List.of(), "I", code.getMethodImplementation()),
                Fixtures.method("second", List.of(), "I", code.getMethodImplementation()));
        var specs = List.of(new TransformerSpec("test.constant", new TransformerOptions(Map.of("value", 73))),
                new TransformerSpec("np.method-hiding.cleanup"));
        var app = new Deobfuscator(TransformerRegistry.discover());
        var events = new ArrayList<EngineProgress>();
        var observed = app.transform(dex, specs, 20, events::add);
        assertEquals(JsonReport.write(app.transform(dex, specs, 20), true), JsonReport.write(observed, true));
        assertEquals(EngineProgress.Phase.PREPARING, events.get(0).phase());
        assertTrue(events.stream().allMatch(e -> e.totalMethods() == 2));
        assertTrue(events.stream().anyMatch(e -> e.phase() == EngineProgress.Phase.METHODS && e.completedMethods() == 1
                && e.round() == 2 && e.transformer().equals("test.constant") && e.method().contains("second")));
        var last = events.get(events.size() - 1);
        assertEquals(EngineProgress.Phase.FINALIZING, last.phase());
        assertEquals(2, last.completedMethods());
    }
}
