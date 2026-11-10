# NP third batch

Frozen original DEX files from the four supplied fixture-v2 APKs. Local analysis and runtime evidence are retained in `tmp/np-batch3/` and are not versioned.

The reflection input already changes isolated UTF-16 surrogates to question marks (219/220 against the original host oracle). Resource references remain plain `sget R$string`; this is not evidence that resource-ID decryption is supported.

- `encrypt-resource.dex` SHA-256 `e1ea28fddeb8f807a091b805db3d1d9a9bec2bd7ae63d63a20294efd21195be9`
- `hide-methods.dex` SHA-256 `7212c2b10d369dd40c5cf80e304f4e0ffaaf6e92e1e6a003e4a53132d899bc33`
- `opt.dex` SHA-256 `9d38c23fc08ee4cd342b358e963564cb9d66696de79ecf8bbef0928c6781cef6`
- `reflect.dex` SHA-256 `cb611718dcef5f5e2210899242bbead436d11822a7969c65f7491a70e6de5890`
