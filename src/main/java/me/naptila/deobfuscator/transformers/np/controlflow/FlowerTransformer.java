package me.naptila.deobfuscator.transformers.np.controlflow;

import java.util.Set;

import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.DexPass;
import me.naptila.deobfuscator.dex.MethodContext;
import me.naptila.deobfuscator.transformers.np.NpTransformer;

public final class FlowerTransformer extends NpTransformer {
   @Override
   public String id() {
      return "np.flower";
   }

   public PassResult run(MethodContext context) {
      Set<Integer> switches = FlowerPatterns.find(context.graph(), this.model);
      Set<Integer> comparisons = ComparisonDispatchers.find(context.graph());
      return switches.isEmpty() && comparisons.isEmpty()
         ? PassResult.unchanged()
         : new DispatcherRecovery(this.model, true, true).run(context, switches, comparisons);
   }

    public static final class Provider extends NpTransformer.Provider {
       @Override
       public String id() {
          return "np.flower";
       }

       @Override
       public String displayName() { return "Junk-code recovery"; }
        public String description() { return "Recover XOR/hash dispatchers, including switches and comparison chains."; }

       @Override
       public DexPass create(TransformerOptions options) {
          options.requireOnly();
          return new FlowerTransformer();
       }
    }
}
