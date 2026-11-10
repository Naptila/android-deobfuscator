package me.naptila.deobfuscator.strings;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

public final class StringFogXorDecoder implements StringDecoder {
   private final String signature;

   public StringFogXorDecoder(String signature) {
      if (!signature.matches("L[^;]+;->[^()]+\\(Ljava/lang/String;Ljava/lang/String;\\)Ljava/lang/String;")) {
         throw new IllegalArgumentException("Expected owner->method(String,String):String DEX signature");
      }

      this.signature = signature;
   }

   @Override
   public String id() {
      return "stringfog-base64-xor:" + this.signature;
   }

   @Override
   public boolean supports(String methodSignature) {
      return this.signature.equals(methodSignature);
   }

   @Override
   public Optional<String> decode(String methodSignature, List<Object> arguments) {
      if (this.supports(methodSignature) && arguments.size() == 2 && arguments.get(0) instanceof String cipher && arguments.get(1) instanceof String key) {
         try {
            byte[] bytes = Base64.getDecoder().decode(cipher.replaceAll("[\\t\\n\\r ]", ""));
            byte[] secret = Base64.getDecoder().decode(key.replaceAll("[\\t\\n\\r ]", ""));
            if (bytes.length != 0 && secret.length == 0) {
               return Optional.empty();
            }

            for (int i = 0; i < bytes.length; i++) {
               bytes[i] ^= secret[i % secret.length];
            }

            return Optional.of(new String(bytes, StandardCharsets.UTF_8));
         } catch (IllegalArgumentException invalidBase64) {
            return Optional.empty();
         }
      } else {
         return Optional.empty();
      }
   }
}
