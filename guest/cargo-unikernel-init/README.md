# cargo-unikernel-init

Minimal guest PID-1 embedded into every image built by
[`cargo-unikernel`](https://codeberg.org/hacer-bark/cargo-unikernel). Brings up the guest
environment, drops privileges, execs the embedded app, and watches over it for the rest of
the boot.

Internal to `cargo-unikernel` — not published or intended for standalone use.
