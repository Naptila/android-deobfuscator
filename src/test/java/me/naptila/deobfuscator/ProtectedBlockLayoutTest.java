package me.naptila.deobfuscator;

import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import java.nio.file.Path;
import java.util.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.TwoRegisterInstruction;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.jf.dexlib2.immutable.value.ImmutableIntEncodedValue;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class ProtectedBlockLayoutTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    private static final String OWNER="Lsample/Test;";
    private static final ImmutableFieldReference TRACE=new ImmutableFieldReference(OWNER,"trace","I");
    private Method fixture(boolean nested, boolean runtimeFirst) {
        var b=new MethodImplementationBuilder(8);Fixtures.integer(b,0,41);
        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT,0,TRACE));Fixtures.go(b,"load");
        b.addLabel("null");b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION,2));
        if(nested) {
            b.addLabel("nestedStart");b.addInstruction(new BuilderInstruction23x(Opcode.AGET_BYTE,1,6,7));b.addLabel("nestedEnd");Fixtures.go(b,"done");
        } else {
            b.addInstruction(new BuilderInstruction22s(Opcode.ADD_INT_LIT16,0,0,2000));
            b.addInstruction(new BuilderInstruction21c(Opcode.SPUT,0,TRACE));b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,0));
        }
        b.addLabel("done");b.addInstruction(new BuilderInstruction23x(Opcode.ADD_INT,0,0,1));
        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT,0,TRACE));b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,0));
        b.addLabel("range");b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION,2));
        b.addInstruction(new BuilderInstruction22s(Opcode.ADD_INT_LIT16,0,0,1000));
        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT,0,TRACE));b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,0));
        b.addLabel("load");b.addInstruction(new BuilderInstruction23x(Opcode.AGET_BYTE,1,5,7));b.addLabel("end");Fixtures.go(b,"done");
        if(runtimeFirst) {
            b.addCatch("Ljava/lang/RuntimeException;",b.getLabel("load"),b.getLabel("end"),b.getLabel("range"));
            b.addCatch("Ljava/lang/NullPointerException;",b.getLabel("load"),b.getLabel("end"),b.getLabel("null"));
        } else {
            b.addCatch("Ljava/lang/NullPointerException;",b.getLabel("load"),b.getLabel("end"),b.getLabel("null"));
            b.addCatch("Ljava/lang/IndexOutOfBoundsException;",b.getLabel("load"),b.getLabel("end"),b.getLabel("range"));
        }
        if(nested) {
            b.addLabel("outer");b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION,2));
            b.addInstruction(new BuilderInstruction22s(Opcode.ADD_INT_LIT16,0,0,3000));
            b.addInstruction(new BuilderInstruction21c(Opcode.SPUT,0,TRACE));b.addInstruction(new BuilderInstruction11x(Opcode.RETURN,0));
            b.addCatch(b.getLabel("nestedStart"),b.getLabel("nestedEnd"),b.getLabel("outer"));
        }
        return Fixtures.method("flow",List.of(new ImmutableMethodParameter("[B",Set.of(),null),new ImmutableMethodParameter("[B",Set.of(),null),
                new ImmutableMethodParameter("I",Set.of(),null)),"I",b.getMethodImplementation());
    }
    private DexFile dex(Method method) {
        var field=new ImmutableField(OWNER,"trace","I",AccessFlags.STATIC.getValue(),new ImmutableIntEncodedValue(0),Set.of(),Set.of());
        return new ImmutableDexFile(Opcodes.forApi(28),List.of(new ImmutableClassDef(OWNER,1,"Ljava/lang/Object;",List.of(),null,Set.of(),List.of(field),List.of(method))));
    }
    private Map<Integer,List<String>> coverage(Method method) {
        var g=new CodeGraph(method.getImplementation());Map<Integer,List<String>> result=new TreeMap<>();
        for(int i=0;i<g.size();i++)if(g.at(i).getOpcode()==Opcode.AGET_BYTE)
            result.put(((TwoRegisterInstruction)g.at(i)).getRegisterB(),g.protection(i).stream().map(CodeGraph.Handler::type).toList());
        return result;
    }
    private Method rewrite(Method input,String name)throws Exception {
        var context=new MethodContext(input);int rounds=0;
        while(BlockLayout.run(context)!=0){rounds++;assertTrue(rounds<8);}assertTrue(rounds>0);
        Path path=directory.getRoot().toPath().resolve(name+".dex");DexFiles.write(path,dex(context.finish()));
        Method output=new DexContext(DexFiles.read(path)).findMethod(Signatures.of(input)).orElseThrow();
        assertEquals(coverage(input),coverage(output));assertEquals(0,BlockLayout.run(new MethodContext(output)));return output;
    }
    @Test public void typedHandlersKeepOrderLocalsAndSideEffectsAfterSerialization()throws Exception {
        Method input=fixture(false,false),output=rewrite(input,"typed");
        for(byte[] array:new byte[][]{null,new byte[0],new byte[]{-3,9}})for(int index:new int[]{-1,0,1,100}) {
            var before=new NpNumericInterpreter(dex(input));var after=new NpNumericInterpreter(dex(output));
            assertEquals(before.run(Signatures.of(input),array,null,index),after.run(Signatures.of(output),array,null,index));
            assertEquals(before.field(Signatures.of(TRACE)),after.field(Signatures.of(TRACE)));
        }
    }
    @Test public void aBroaderEarlierHandlerKeepsItsPrecedence()throws Exception {
        Method input=fixture(false,true),output=rewrite(input,"precedence");
        var before=new NpNumericInterpreter(dex(input));var after=new NpNumericInterpreter(dex(output));
        assertEquals(1041,before.run(Signatures.of(input),null,null,0));
        assertEquals(1041,after.run(Signatures.of(output),null,null,0));
        assertEquals(List.of("Ljava/lang/RuntimeException;","Ljava/lang/NullPointerException;"),coverage(output).get(5));
    }
    @Test public void exceptionsInsideAHandlerReachTheOriginalOuterCatchAll()throws Exception {
        Method input=fixture(true,false),output=rewrite(input,"nested");
        for(byte[] primary:new byte[][]{null,new byte[0],new byte[]{2}})
            for(byte[] fallback:new byte[][]{null,new byte[0],new byte[]{7}})for(int index:new int[]{-1,0,1}) {
                var before=new NpNumericInterpreter(dex(input));var after=new NpNumericInterpreter(dex(output));
                assertEquals(before.run(Signatures.of(input),primary,fallback,index),after.run(Signatures.of(output),primary,fallback,index));
                assertEquals(before.field(Signatures.of(TRACE)),after.field(Signatures.of(TRACE)));
            }
    }
}
