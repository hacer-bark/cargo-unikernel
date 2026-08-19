# cargo-unikernel-init

Minimal guest PID-1 embedded into every image built by
[`cargo-unikernel`](https://codeberg.org/hacer-bark/cargo-unikernel). Brings up the guest
environment (filesystem/network mounts, sysctl hardening, entropy wait), drops privileges,
execs the embedded app, installs the seccomp denylist, and watches over the app for the rest
of the boot — then runs the wipe-and-power-off shutdown protocol on either a graceful stop or
any integrity-compromising failure.

Internal to `cargo-unikernel` — not published or intended for standalone use.
