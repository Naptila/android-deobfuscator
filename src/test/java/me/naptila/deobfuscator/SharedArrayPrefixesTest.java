package me.naptila.deobfuscator;

import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import java.nio.file.Path;
import java.util.*;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class SharedArrayPrefixesTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    private List<ImmutableMethodParameter> parameters(String... types) {
        return Arrays.stream(types).map(t -> new ImmutableMethodParameter(t, Set.of(), null)).toList();
    }
    private Method fixture(Opcode factory, boolean separatePrefixes, boolean reference, String hazard) {
        String type = reference ? "[Ljava/lang/String;" : "[I";
        var b = new MethodImplementationBuilder(8);
        if (hazard.equals("debug")) b.addLineNumber(71);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ,6,b.getLabel("missing")));
        b.addInstruction(new BuilderInstruction12x(Opcode.ARRAY_LENGTH,0,6)); Fixtures.integer(b,3,1);
        b.addInstruction(new BuilderInstruction22t(Opcode.IF_LT,0,3,b.getLabel(separatePrefixes ? "short" : "missing")));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT,1,6)); Fixtures.go(b,"join");
        b.addLabel("missing");
        b.addInstruction(new BuilderInstruction12x(reference ? Opcode.MOVE_OBJECT : Opcode.MOVE,2,7)); Fixtures.go(b,"factory");
        if (separatePrefixes) {
            b.addLabel("short"); b.addInstruction(new BuilderInstruction12x(reference ? Opcode.MOVE_OBJECT : Opcode.MOVE,2,7)); Fixtures.go(b,"factory");
        }
        b.addLabel("factory");
        if (hazard.equals("loop")) Fixtures.go(b,"factory");
        if (factory == Opcode.NEW_ARRAY) b.addInstruction(new BuilderInstruction22c(factory,1,2,new ImmutableTypeReference(type)));
        else {
            b.addInstruction(factory == Opcode.FILLED_NEW_ARRAY
                    ? new BuilderInstruction35c(factory,1,2,0,0,0,0,new ImmutableTypeReference(type))
                    : new BuilderInstruction3rc(factory,2,1,new ImmutableTypeReference(type)));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT,1));
        }
        if (hazard.equals("second-array")) {
            Fixtures.integer(b,4,0); b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY,5,4,new ImmutableTypeReference("[I")));
        }
        if (hazard.equals("business-call")) b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC,1,2,0,0,0,0,
                new ImmutableMethodReference("Lunknown/Effects;","observe",List.of("I"),"V")));
        if (hazard.equals("monitor")) {
            b.addInstruction(new BuilderInstruction11x(Opcode.MONITOR_ENTER,1));
            b.addInstruction(new BuilderInstruction11x(Opcode.MONITOR_EXIT,1));
        }
        Fixtures.go(b,"join"); b.addLabel("join"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT,1));
        if (hazard.equals("protected")) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION,0));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT,6));
            b.addCatch("Ljava/lang/Exception;",b.getLabel("factory"),b.getLabel("join"),b.getLabel("handler"));
        }
        return Fixtures.method("flow",parameters(type, reference ? "Ljava/lang/String;" : "I"),type,b.getMethodImplementation());
    }
    private Method rewrite(Method input, String name) throws Exception {
        var context = new MethodContext(input); int count = 0;
        while (SharedConditionalRegions.runArrayPrefixes(context) != 0) { count++; assertTrue(count < 8); }
        assertTrue(count > 0);
        Path file = directory.getRoot().toPath().resolve(name+".dex"); DexFiles.write(file,Fixtures.dex(context.finish()));
        Method output = Fixtures.first(DexFiles.read(file));
        assertEquals(0,SharedConditionalRegions.runArrayPrefixes(new MethodContext(output)));
        return output;
    }
    @Test public void eachPathAllocatesExactlyOnceOrRetainsItsInputArray() throws Exception {
        int index=0;
        for (Opcode factory : List.of(Opcode.NEW_ARRAY,Opcode.FILLED_NEW_ARRAY,Opcode.FILLED_NEW_ARRAY_RANGE))
            for (boolean separate : List.of(false,true)) {
                Method input=fixture(factory,separate,false,"");Method output=rewrite(input,"primitive-"+index++);
                for (int[] array : new int[][]{null,new int[0],new int[]{1},new int[]{3,4,5}}) for (int value : new int[]{0,1,3}) {
                    var before=new NpNumericInterpreter(Fixtures.dex(input));var after=new NpNumericInterpreter(Fixtures.dex(output));
                    Object expected=before.run(Signatures.of(input),array,value),actual=after.run(Signatures.of(output),array,value);
                    assertArrayEquals((int[])expected,(int[])actual);
                    int allocations=array==null||array.length==0?1:0;
                    assertEquals(allocations,before.allocationAttempts());assertEquals(allocations,after.allocationAttempts());
                    if(allocations==0)assertSame(array,actual);else assertNotSame(array,actual);
                }
            }
    }
    @Test public void referenceElementsAndNullKeepTheirIdentityWithBothFilledArrayEncodings() throws Exception {
        int index=0;
        for(Opcode factory:List.of(Opcode.FILLED_NEW_ARRAY,Opcode.FILLED_NEW_ARRAY_RANGE)) {
            Method input=fixture(factory,true,true,"");Method output=rewrite(input,"reference-"+index++);
            for(String[] array:new String[][]{null,new String[0],new String[]{"existing"}})
                for(String value:new String[]{null,new String(""),new String("元素🙂")}) {
                    var before=new NpNumericInterpreter(Fixtures.dex(input));var after=new NpNumericInterpreter(Fixtures.dex(output));
                    String[] expected=(String[])before.run(Signatures.of(input),array,value);
                    String[] actual=(String[])after.run(Signatures.of(output),array,value);
                    assertArrayEquals(expected,actual);
                    if(array!=null&&array.length>0)assertSame(array,actual);else assertSame(value,actual[0]);
                    assertEquals(before.allocationAttempts(),after.allocationAttempts());
                }
        }
    }
    @Test public void aThrowingAllocationKeepsItsPathAndSuccessfulAlternative() throws Exception {
        Method input=fixture(Opcode.NEW_ARRAY,true,false,"");Method output=rewrite(input,"throwing");
        for(int[] array:new int[][]{null,new int[0]}) {
            var before=new NpNumericInterpreter(Fixtures.dex(input));var after=new NpNumericInterpreter(Fixtures.dex(output));
            assertThrows(NegativeArraySizeException.class,()->before.run(Signatures.of(input),array,-3));
            assertThrows(NegativeArraySizeException.class,()->after.run(Signatures.of(output),array,-3));
            assertEquals(1,before.allocationAttempts());assertEquals(1,after.allocationAttempts());
        }
        int[] existing={9};var after=new NpNumericInterpreter(Fixtures.dex(output));
        assertSame(existing,after.run(Signatures.of(output),existing,-3));assertEquals(0,after.allocationAttempts());
    }
    @Test public void rejectsExceptionRangesDebugInfoBusinessCallsMultipleFactoriesAndCycles() {
        for(String hazard:List.of("protected","debug","business-call","second-array","loop","monitor")) {
            Method input=fixture(Opcode.NEW_ARRAY,true,false,hazard);var context=new MethodContext(input);
            assertEquals(hazard,0,SharedConditionalRegions.runArrayPrefixes(context));
        }
    }
    @Test public void plainPrivateArrayPrefixDoesNotGrowOnRepeatedRuns() {
        var b=new MethodImplementationBuilder(3);Fixtures.integer(b,0,1);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ,2,b.getLabel("factory")));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT,2));
        b.addLabel("factory");b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY,1,0,new ImmutableTypeReference("[I")));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT,1));
        Method input=Fixtures.method("flow",parameters("[I"),"[I",b.getMethodImplementation());
        assertEquals(0,SharedConditionalRegions.runArrayPrefixes(new MethodContext(input)));
    }
    @Test public void normalNpCleanupSplitsThePrefixBeforeFinalLayout() throws Exception {
        Method input=fixture(Opcode.FILLED_NEW_ARRAY,true,false,"");
        var code=new MutableMethodImplementation(input.getImplementation());
        code.addInstruction(0,new BuilderInstruction21c(Opcode.CONST_STRING,4,new ImmutableStringReference("array")));
        code.addInstruction(1,new BuilderInstruction35c(Opcode.INVOKE_STATIC,1,4,0,0,0,0,Fixtures.NP_HASH));
        Method withNp=new ImmutableMethod(input.getDefiningClass(),input.getName(),input.getParameters(),input.getReturnType(),input.getAccessFlags(),Set.of(),Set.of(),code);
        var result=new Deobfuscator(TransformerRegistry.discover()).transform(Fixtures.npDex(withNp),RunConfiguration.defaults().transformers(),20);
        assertEquals(0,result.failedMethods());assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged));
        Method output=new DexContext(result.dex()).findMethod(Signatures.of(withNp)).orElseThrow();
        assertEquals(0,SharedConditionalRegions.runArrayPrefixes(new MethodContext(output)));
        for(int[] array:new int[][]{null,new int[0],new int[]{2,3}}) {
            var before=new NpNumericInterpreter(Fixtures.dex(input));var after=new NpNumericInterpreter(Fixtures.dex(output));
            assertArrayEquals((int[])before.run(Signatures.of(input),array,5),(int[])after.run(Signatures.of(output),array,5));
            assertEquals(before.allocationAttempts(),after.allocationAttempts());
        }
    }
}
