package me.naptila.deobfuscator.strings;

import java.util.List;
import java.util.Optional;

/** Offline model for a specific static decryptor; never executes target application code. */
public interface StringDecoder {
    String id();
    /** Exact DEX signature, including owner, parameters, and return type. */
    boolean supports(String methodSignature);
    /** Must model the actual method for these arguments; unknown arguments are represented by null. */
    Optional<String> decode(String methodSignature, List<Object> arguments);
}
