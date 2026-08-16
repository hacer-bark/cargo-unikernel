# Bringing your app in: three options compared

*[docs index](README.md) · [project README](../README.md)*

`cargo-unikernel` needs your app as a binary to embed in the image. Three ways to get
there, in increasing setup and decreasing "how much has to already be true about your
project":

| | Rust source build | Generic source build | Bring your own binary |
|:---|:---|:---|:---|
| Config | zero-config, or `toolchain = "rust"` | `toolchain = "generic"` | `app.mode = "binary"` |
| Runs in container | `cargo build --target x86_64-unknown-linux-musl` | your `build_command` | nothing — staged, not built |
| Trust anchor | the pinned Rust toolchain | whatever `build_command` pulls in | whoever produced the binary |
| Works with | any Cargo project | any language whose output is one binary | any already-compiled binary |
| Extra setup | none | `build_command` + `output_binary` | local `path` |
| Example | `cargo-unikernel.casual.toml`'s `[app.source]` | same file, `toolchain = "generic"` alternative | same file, `[app.binary]` alternative |

## Rust source build (the default)

Run `cargo unikernel build` in a directory with a `Cargo.toml` and it just works — project
name, source location, and build command are all inferred. This is the only path that
supports full auto-detection.

## Generic source build (any other language)

Same pipeline as the Rust path (same container, same "source never leaves your machine as
anything but source") except the last-mile build step is a shell command you supply:

```toml
[app.source]
path = "."
toolchain = "generic"
build_command = "CGO_ENABLED=0 GOOS=linux go build -o app ."
output_binary = "app"
extra_apt_packages = []   # only if your toolchain isn't already in the build image
```

**The binary must have no dynamic dependencies** — there's no dynamic linker or libc in the
minimal rootfs to satisfy one. Statically link (`CGO_ENABLED=0` for Go, `-Dtarget=…-musl`
for Zig, `cc -static` for C), the same way the Rust path cross-compiles to
`x86_64-unknown-linux-musl`. This is checked automatically for every mode: the build fails
immediately, naming any missing shared libraries, if the binary has a dynamic-linker segment
or `DT_NEEDED` entries — instead of shipping an image that only fails at boot.

`extra_apt_packages` covers a toolchain not already in `Dockerfile.reproducible` (Go is
already included). Limited to whatever `apt-get install` can provide in the Ubuntu build
image — not a hand-rolled installer script.

## Bring your own binary

For anything already compiled:

```toml
[app]
mode = "binary"

[app.binary]
path = "./target/release/my-app"     # a local file only — never fetched over the network
```

No compiler runs in the container — the binary is staged host-side from `path`, then
embedded like the other paths' output. This is the only mode where the trust anchor moves
from "the pinned build toolchain" to "whoever produced this binary" — and since it's always
a local file, that trust decision was already made before `cargo-unikernel` ever saw it.

## Which one should I use?

- **Already a Rust project?** Use the default.
- **Another language, can produce a static binary?** Generic source build — same
  reproducibility story, one extra config section.
- **Already have a binary, or don't want to rebuild here?** Bring your own binary — fastest,
  different trust model.
