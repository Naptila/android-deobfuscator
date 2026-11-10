package me.naptila.deobfuscator.transformers.np.strings;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.ConstantAnalysis;
import me.naptila.deobfuscator.dex.DexPass;
import me.naptila.deobfuscator.dex.Edits;
import me.naptila.deobfuscator.dex.MethodContext;
import me.naptila.deobfuscator.dex.Signatures;
import me.naptila.deobfuscator.transformers.np.NpTransformer;
import me.naptila.deobfuscator.transformers.np.analysis.NpHelpers;

import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.BuilderInstruction;
import org.jf.dexlib2.iface.instruction.Instruction;

public final class StringTransformer extends NpTransformer {
   public StringTransformer() {
      this(false);
   }

   public StringTransformer(boolean closedWorld) {
      super(closedWorld);
   }

   public StringTransformer(boolean closedWorld, Set<String> assumed) {
      super(closedWorld, assumed);
   }

   @Override
   public String id() {
      return "np.strings";
   }

   public PassResult run(MethodContext context) {
      boolean hasDecoder = false;

      for (BuilderInstruction instruction : context.code().getInstructions()) {
         if (NpStringCalls.isDecoder(this.model, instruction) || NpStringCalls.isConstantGetter(this.model, instruction)
               || NpStringCalls.isProxy(this.model, instruction)) {
            hasDecoder = true;
            break;
         }
      }

      if (!hasDecoder) {
         return PassResult.unchanged();
      }

      CodeGraph graph = context.graph();
      if (!this.applies(context, graph) && !this.model.stringGetters().containsKey(Signatures.of(context.original()))) {
         return PassResult.unchanged();
      }

      ConstantAnalysis facts = new ConstantAnalysis(graph, (i, state) -> {
         String value = NpStringCalls.value(this.model, i, state);
         this.model.step(i, state);
         if (value != null) state.result(value);
      }, true, true);
      List<Edits.Edit> edits = new ArrayList<>();
      int skipped = 0;
      int getters = 0;
      int proxies = 0;

      for (int i = 0; i < graph.size(); i++) {
         Instruction insn = graph.at(i);
         if (NpStringCalls.isDecoder(this.model, insn) || NpStringCalls.isConstantGetter(this.model, insn) || NpStringCalls.isProxy(this.model, insn)) {
            var state = facts.before(i);
            String value = NpStringCalls.value(this.model, insn, state);
            // Preserve the successful decoding proof for the shared cleanup tail,
            // including calls whose result has already been replaced or is unused.
            if (value != null && NpStringCalls.removable(this.model, insn, state))
               context.recordDecodedStringCall(context.code().getInstructions().get(i));
            if (i + 1 == graph.size() || graph.at(i + 1).getOpcode() != Opcode.MOVE_RESULT_OBJECT
                  || graph.leaders().contains(i + 1) || state == null) continue;
            if (value == null) {
               skipped++;
            } else {
               edits.add(new Edits.Edit(i + 1, false, List.of(Edits.constant(NpHelpers.reg(graph.at(i + 1)), value))));
               if (NpStringCalls.isConstantGetter(this.model, insn)) getters++;
               else if (NpStringCalls.isProxy(this.model, insn)) proxies++;
            }
         }
      }

      Edits.apply(context.code(), edits);
      List<String> notes = new ArrayList<>();
      if (skipped != 0) notes.add("unproven NP string calls: " + skipped);
      if (getters != 0) notes.add("NP string getter results restored (calls retained): " + getters);
      if (proxies != 0) notes.add("NP string proxy results restored (calls retained): " + proxies);
      return new PassResult(edits.size(), notes);
   }

    public static final class Provider extends NpTransformer.Provider {
       @Override
       public String id() {
          return "np.strings";
       }

       public String displayName() { return "NP string decryption"; }

       @Override
       public String description() {
          return "Decode known strings from short-array XOR decryptors. Cleanup verifies calls and string tables.";
       }

       @Override
       public DexPass create(TransformerOptions options) {
          options.requireOnly("assumeClosedWorld", "assumeImmutableTables", "removeProtectedStringCalls");
          options.bool("removeProtectedStringCalls");
          boolean closedWorld = options.bool("assumeClosedWorld");
          Set<String> tables = Set.copyOf(options.strings("assumeImmutableTables"));
          for (String field : tables) {
             if (!field.matches("L[^;]+;->[^:]+:\\[S"))
                throw new IllegalArgumentException("assumeImmutableTables requires exact short[] field signatures");
          }
          return new StringTransformer(closedWorld, tables);
       }
       @Override
       public List<TransformerSpec> cleanup(TransformerOptions options) {
          var steps = new ArrayList<>(super.cleanup(options));
          var cleanup = TransformerOptions.empty();
          for (String key : List.of("assumeClosedWorld", "removeProtectedStringCalls"))
             if (options.values().containsKey(key)) cleanup = cleanup.with(key, options.bool(key));
          if (options.values().containsKey("assumeImmutableTables"))
             cleanup = cleanup.with("assumeImmutableTables", options.strings("assumeImmutableTables"));
          steps.set(steps.size() - 1, new TransformerSpec("np.cleanup", cleanup));
          return List.copyOf(steps);
       }
    }
}
