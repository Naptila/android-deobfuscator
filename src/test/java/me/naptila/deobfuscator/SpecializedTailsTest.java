package me.naptila.deobfuscator;

import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import java.nio.file.Path;
import java.util.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.jf.dexlib2.immutable.value.ImmutableIntEncodedValue;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class SpecializedTailsTest {
    @Rule public TemporaryFolder directory=new TemporaryFolder();
    private static final String OWNER="Lsample/Test;";
    private static final ImmutableFieldReference TRACE=new ImmutableFieldReference(OWNER,"trace","I");
    private static final ImmutableMethodReference EFFECT=new ImmutableMethodReference(OWNER,"effect",List.of("I"),"I");
    private static final int[] VALUES={Integer.MIN_VALUE,-2,-1,0,1,2,Integer.MAX_VALUE};
    private List<ImmutableMethodParameter> params(String... types){return Arrays.stream(types).map(t->new ImmutableMethodParameter(t,Set.of(),null)).toList();}
    private Method fixture(String hazard) {
        var b=new MethodImplementationBuilder(8);Fixtures.integer(b,0,0);b.addInstruction(new BuilderInstruction21c(Opcode.SPUT,0,TRACE));
        if(hazard.equals("debug"))b.addLineNumber(9);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ,6,b.getLabel("false")));
        Fixtures.integer(b,2,1);Fixtures.go(b,"common");
        b.addLabel("false");Fixtures.integer(b,2,0);Fixtures.go(b,"common");
        b.addLabel("common");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC,1,6,0,0,0,0,EFFECT));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT,hazard.equals("opaque-write")?2:0));
        b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY,3,7,new ImmutableTypeReference("[I")));
        if(hazard.equals("monitor")){b.addInstruction(new BuilderInstruction11x(Opcode.MONITOR_ENTER,3));b.addInstruction(new BuilderInstruction11x(Opcode.MONITOR_EXIT,3));}
        if(hazard.equals("loop"))Fixtures.go(b,"common");
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ,2,b.getLabel("no")));
        Fixtures.integer(b,4,11);Fixtures.go(b,"result");
        b.addLabel("no");Fixtures.integer(b,4,22);
        b.addLabel("result");b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT,4,4,6));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC,1,4,0,0,0,0,EFFECT));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT,0));b.addLabel("end");b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,0));
        if(hazard.equals("protected")) {
            b.addLabel("handler");b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION,0));
            Fixtures.integer(b,0,-1);b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,0));
            b.addCatch("Ljava/lang/Exception;",b.getLabel("common"),b.getLabel("end"),b.getLabel("handler"));
        }
        return Fixtures.method("flow",params("I","I"),"I",b.getMethodImplementation());
    }
    private DexFile dex(Method method) {
        var b=new MethodImplementationBuilder(3);b.addInstruction(new BuilderInstruction21c(Opcode.SGET,0,TRACE));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8,0,0,1));b.addInstruction(new BuilderInstruction21c(Opcode.SPUT,0,TRACE));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,2));Method effect=Fixtures.method("effect",params("I"),"I",b.getMethodImplementation());
        var trace=new ImmutableField(OWNER,"trace","I",AccessFlags.STATIC.getValue(),new ImmutableIntEncodedValue(0),Set.of(),Set.of());
        return new ImmutableDexFile(Opcodes.forApi(28),List.of(new ImmutableClassDef(OWNER,1,"Ljava/lang/Object;",List.of(),null,Set.of(),List.of(trace),List.of(method,effect))));
    }
    private Method rewrite(Method input,String name)throws Exception {
        var context=new MethodContext(input);int count=0;
        while(SpecializedTails.run(context)!=0){count++;assertTrue(count<8);}assertTrue(count>0);
        Path file=directory.getRoot().toPath().resolve(name+".dex");DexFiles.write(file,dex(context.finish()));
        Method output=new DexContext(DexFiles.read(file)).findMethod(Signatures.of(input)).orElseThrow();
        assertEquals(0,SpecializedTails.run(new MethodContext(output)));return output;
    }
    @Test public void specializesOnlyKnownBranchesAndPreservesCallsAllocationsAndOverflow()throws Exception {
        Method input=fixture(""),output=rewrite(input,"normal");
        for(int value:VALUES)for(int size:new int[]{0,1,3}) {
            var before=new NpNumericInterpreter(dex(input));var after=new NpNumericInterpreter(dex(output));
            assertEquals(before.run(Signatures.of(input),value,size),after.run(Signatures.of(output),value,size));
            assertEquals(2,before.field(Signatures.of(TRACE)));assertEquals(2,after.field(Signatures.of(TRACE)));
            assertEquals(1,before.allocationAttempts());assertEquals(1,after.allocationAttempts());
        }
    }
    @Test public void aThrowSuppressesLaterSideEffectsAndRetainsEarlierOnes()throws Exception {
        Method input=fixture(""),output=rewrite(input,"throwing");
        for(int value:VALUES) {
            var before=new NpNumericInterpreter(dex(input));var after=new NpNumericInterpreter(dex(output));
            assertThrows(NegativeArraySizeException.class,()->before.run(Signatures.of(input),value,-1));
            assertThrows(NegativeArraySizeException.class,()->after.run(Signatures.of(output),value,-1));
            assertEquals(1,before.field(Signatures.of(TRACE)));assertEquals(1,after.field(Signatures.of(TRACE)));
            assertEquals(1,before.allocationAttempts());assertEquals(1,after.allocationAttempts());
        }
    }
    @Test public void opaqueResultsCyclesMonitorsExceptionsAndDebugInfoPreventSpecialization() {
        for(String hazard:List.of("opaque-write","loop","monitor","protected","debug"))
            assertEquals(hazard,0,SpecializedTails.run(new MethodContext(fixture(hazard))));
    }
    @Test public void aPlainSharedCallTailIsNotSpecializedWithoutAProvenBranch() {
        var b=new MethodImplementationBuilder(3);b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ,2,b.getLabel("left")));
        Fixtures.integer(b,0,1);Fixtures.go(b,"common");b.addLabel("left");Fixtures.integer(b,0,2);
        b.addLabel("common");b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC,1,0,0,0,0,0,EFFECT));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT,1));b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,1));
        assertEquals(0,SpecializedTails.run(new MethodContext(Fixtures.method("flow",params("I"),"I",b.getMethodImplementation()))));
    }
    @Test public void fullPipelineConvergesAndUsesTheNewProof() {
        Method input=fixture("");var code=new MutableMethodImplementation(input.getImplementation());
        code.addInstruction(0,new BuilderInstruction21c(Opcode.CONST_STRING,4,new ImmutableStringReference("tail")));
        code.addInstruction(1,new BuilderInstruction35c(Opcode.INVOKE_STATIC,1,4,0,0,0,0,Fixtures.NP_HASH));
        Method withNp=new ImmutableMethod(OWNER,input.getName(),input.getParameters(),input.getReturnType(),input.getAccessFlags(),Set.of(),Set.of(),code);
        var classes=new ArrayList<ClassDef>(Fixtures.npDex().getClasses());classes.removeIf(c->c.getType().equals(OWNER));classes.addAll(dex(withNp).getClasses());
        var result=new Deobfuscator(TransformerRegistry.discover()).transform(new ImmutableDexFile(Opcodes.forApi(28),classes),RunConfiguration.defaults().transformers(),20);
        assertEquals(0,result.failedMethods());assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged));
        assertTrue(result.methods().stream().flatMap(m->m.steps().stream()).flatMap(s->s.result().notes().stream())
                .anyMatch(s->s.startsWith("constant terminal traces specialized:")));
    }
}
