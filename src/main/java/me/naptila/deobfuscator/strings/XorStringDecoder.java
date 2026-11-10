package me.naptila.deobfuscator.strings;

import java.util.*;

/** Explicit opt-in model: each UTF-16 char is XORed with the integer key, then cast to char. */
public final class XorStringDecoder implements StringDecoder {
    private final String signature;
    public XorStringDecoder(String signature) {
        if (!signature.matches("L[^;]+;->[^()]+\\(Ljava/lang/String;I\\)Ljava/lang/String;"))
            throw new IllegalArgumentException("Expected owner->method(String,int):String DEX signature");
        this.signature = signature;
    }
    @Override public String id() { return "xor-utf16:" + signature; }
    @Override public boolean supports(String methodSignature) { return signature.equals(methodSignature); }
    @Override public Optional<String> decode(String methodSignature, List<Object> arguments) {
        if (!supports(methodSignature) || arguments.size() != 2
                || !(arguments.get(0) instanceof String text) || !(arguments.get(1) instanceof Integer key)) return Optional.empty();
        char[] chars = text.toCharArray();
        for (int i = 0; i < chars.length; i++) chars[i] = (char) (chars[i] ^ key);
        return Optional.of(new String(chars));
    }
}
