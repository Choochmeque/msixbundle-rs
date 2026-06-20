# @choochmeque/msixbundle-cli-win32

Prebuilt Windows binaries for [`msixbundle-cli`](https://github.com/Choochmeque/msixbundle-rs), shipped as an `optionalDependencies` sidecar.

This package is **not meant to be used directly**. It is consumed automatically by [`@choochmeque/tauri-windows-bundle`](https://www.npmjs.com/package/@choochmeque/tauri-windows-bundle), which resolves the correct binary at runtime based on `process.arch`.

Contents:

```
bin/
  x64/msixbundle-cli.exe
  arm64/msixbundle-cli.exe
```

Package version tracks the upstream `msixbundle-cli` crate version.

## Source

Built from <https://github.com/Choochmeque/msixbundle-rs> at the matching tag.

## License

MIT — see the [main repository](https://github.com/Choochmeque/msixbundle-rs).
