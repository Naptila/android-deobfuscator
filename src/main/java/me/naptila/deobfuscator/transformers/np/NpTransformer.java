package me.naptila.deobfuscator.transformers.np;

import java.util.List;
import java.util.Set;

import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.DexPass;
import me.naptila.deobfuscator.dex.MethodContext;
import me.naptila.deobfuscator.transform.TransformerProvider;
import me.naptila.deobfuscator.transformers.np.analysis.NpAnalysis;
import me.naptila.deobfuscator.transformers.np.analysis.NpModel;

public abstract class NpTransformer implements DexPass {
   /** Feature providers own their cleanup; the registry shares the common tail across features. */
   public abstract static class Provider implements TransformerProvider {
      public List<TransformerSpec> cleanup(TransformerOptions options) {
         return List.of(new TransformerSpec("dex.constant-switch"), new TransformerSpec("dex.unreachable"),
               new TransformerSpec("np.cleanup"));
      }
   }
   protected NpModel model;

   /** Supply facts for bounded helper analysis on scratch methods; does not register cleanup evidence. */
   public final void prepareModel(NpModel model) { this.model = java.util.Objects.requireNonNull(model); }

   private final boolean closedWorld;
   private final Set<String> assumed;

   protected NpTransformer() {
      this(false);
   }

   protected NpTransformer(boolean closedWorld) {
      this(closedWorld, Set.of());
   }

   protected NpTransformer(boolean closedWorld, Set<String> assumed) {
      this.closedWorld = closedWorld;
      this.assumed = Set.copyOf(assumed);
   }

   @Override
   public final void prepare(DexContext context) {
      this.model = NpAnalysis.withAssumedTables(context, NpAnalysis.model(context, this.closedWorld), this.assumed);
   }

   protected boolean applies(MethodContext context, CodeGraph graph) {
      if (this.model == null) {
         throw new IllegalStateException("NP transformers require DexEngine preparation");
      } else {
         return !this.model.helpers().owners().contains(context.original().getDefiningClass()) && this.model.relevant(graph);
      }
   }
}
