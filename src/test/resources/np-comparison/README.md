# XOR comparison dispatcher fixtures

`debug.dex` and `release.dex` contain the same `FlowTest.synchronizedBlock(I)I`
method extracted from the user-provided June `flow2.0.jar` (SHA-256
`e3c5d577e888384d967e5a18784fe89a6c62b64bee5e33ed684be88e6093c360`).
Only that method and its `base` field were retained in the class, without
rewriting the method body. The JAR was originally exported from an APK using
dex2jar; the original APK is unavailable.

D8 8.6.2-dev (Android build-tools 35.0.0, build
`abaab469b5ebd4dd2bb91ba0ed6f45277faae4ca`) compiled the same class with
`--min-api 26 --no-desugaring`, respectively `--debug` and `--release`.
Debug retains three XOR/switch loops; release lowers all three to equality
chains, including interleaved live constants and an exception-handler loop.

SHA-256:
- debug.dex: `c24d6ed00e3db04b7b51e88efc3c5cb9727cc90fdf68299c00e227e2bfc89540`
- release.dex: `2bf2db4b46d86896b5871061160149bc3ba1ccc4ffa5c5aecbdc0b18eb85285b`

Analysis and extraction scripts are retained in `tmp/june-flow-analysis/`.
