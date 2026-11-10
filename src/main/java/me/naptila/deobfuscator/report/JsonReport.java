package me.naptila.deobfuscator.report;

import me.naptila.deobfuscator.dex.DexEngine;
import me.naptila.deobfuscator.app.FileRunResult;

public final class JsonReport {
    private JsonReport() {}
    public static String write(FileRunResult result, boolean dryRun) {
        if (!result.apk()) return write(result.result(), dryRun);
        String report = write(result.result(), dryRun);
        String owners = String.join(",", result.classOwners().entrySet().stream().sorted(java.util.Map.Entry.comparingByKey())
                .map(entry -> quote(entry.getKey()) + ":" + quote(entry.getValue())).toList());
        return "{\n  \"inputFormat\": \"apk\",\n  \"outputSigning\": " + quote(dryRun ? "not-written" : "unsigned")
                + ",\n  \"dexEntries\": [" + String.join(",", result.dexEntries().stream().map(JsonReport::quote).toList())
                + "],\n  \"signatureEntriesToRemove\": [" + String.join(",", result.removedSignatureEntries().stream().map(JsonReport::quote).toList())
                + "],\n  \"classDexOwners\": {" + owners + "}," + report.substring(1);
    }
    static String quote(String text) {
        if (text == null) return "null";
        StringBuilder out = new StringBuilder("\"");
        for (char c : text.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> { if (c < 32 || Character.isSurrogate(c)) out.append(String.format("\\u%04x", (int)c)); else out.append(c); }
            }
        }
        return out.append('"').toString();
    }
    public static String write(DexEngine.Result result, boolean dryRun) {
        StringBuilder out = new StringBuilder("{\n  \"dryRun\": ").append(dryRun)
                .append(",\n  \"changedMethods\": ").append(result.changedMethods())
                .append(",\n  \"failedMethods\": ").append(result.failedMethods()).append(",\n  \"methods\": [");
        boolean first = true;
        for (var method : result.methods()) {
            if (!first) out.append(','); first = false;
            out.append("\n    {\"method\": ").append(quote(method.method())).append(", \"edits\": ").append(method.edits())
                    .append(", \"converged\": ").append(method.converged()).append(", \"rolledBack\": ").append(method.rolledBack())
                    .append(", \"error\": ").append(quote(method.error())).append(", \"steps\": [");
            boolean firstStep = true;
            for (var step : method.steps()) {
                if (step.result().edits() == 0 && step.result().notes().isEmpty()) continue;
                if (!firstStep) out.append(','); firstStep = false;
                out.append("{\"round\": ").append(step.round()).append(", \"pass\": ").append(quote(step.pass()))
                        .append(", \"edits\": ").append(step.result().edits()).append(", \"notes\": [");
                out.append(String.join(",", step.result().notes().stream().map(JsonReport::quote).toList())).append("]}");
            }
            out.append("]}");
        }
        out.append("\n  ],\n  \"dexEdits\": ").append(result.dexEdits()).append(",\n  \"dexSteps\": [");
        boolean firstDexStep = true;
        for (var step : result.dexSteps()) {
            if (!firstDexStep) out.append(','); firstDexStep = false;
            out.append("\n    {\"pass\": ").append(quote(step.pass())).append(", \"edits\": ").append(step.result().edits())
                    .append(", \"notes\": [")
                    .append(String.join(",", step.result().notes().stream().map(JsonReport::quote).toList())).append("]}");
        }
        out.append("\n  ],\n  \"methodEvidence\": {\n    \"candidates\": [");
        boolean firstEvidence = true;
        for (var candidate : result.evidence().candidates()) {
            if (!firstEvidence) out.append(','); firstEvidence = false;
            out.append("\n      {\"method\": ").append(quote(candidate.method())).append(", \"producer\": ").append(quote(candidate.producer()))
                    .append(", \"rule\": ").append(quote(candidate.rule())).append(", \"originalSha256\": ").append(quote(candidate.originalSha256()))
                    .append(", \"facts\": [").append(String.join(",", candidate.facts().stream().map(JsonReport::quote).toList())).append("]}");
        }
        out.append("\n    ],\n    \"committedReplacements\": ["); firstEvidence = true;
        for (var replacement : result.evidence().replacements()) {
            if (!firstEvidence) out.append(','); firstEvidence = false;
            out.append("\n      {\"producer\": ").append(quote(replacement.producer())).append(", \"target\": ").append(quote(replacement.target()))
                    .append(", \"caller\": ").append(quote(replacement.caller())).append(", \"invocation\": ").append(replacement.invocation())
                    .append(", \"instructionIndex\": ").append(replacement.instructionIndex()).append(", \"codeAddress\": ").append(replacement.codeAddress()).append('}');
        }
        out.append("\n    ],\n    \"decisions\": ["); firstEvidence = true;
        for (var decision : result.evidence().decisions()) {
            if (!firstEvidence) out.append(','); firstEvidence = false;
            out.append("\n      {\"method\": ").append(quote(decision.method())).append(", \"action\": ").append(quote(decision.action()))
                    .append(", \"outputSha256\": ").append(quote(decision.outputSha256())).append(", \"reasons\": [")
                    .append(String.join(",", decision.reasons().stream().map(JsonReport::quote).toList())).append("], \"references\": [")
                    .append(String.join(",", decision.references().stream().map(JsonReport::quote).toList())).append("]}");
        }
        return out.append("\n    ],\n    \"incompleteMethods\": [")
                .append(String.join(",", result.evidence().incompleteMethods().stream().map(JsonReport::quote).toList()))
                .append("]\n  }\n}\n").toString();
    }
}
