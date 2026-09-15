"""Exercise build/cache failure paths without compiling or booting a kernel."""

import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "build_kernel.sh"


class KernelBuildTests(unittest.TestCase):
    def setUp(self):
        fixture_root = Path(__file__).resolve().parents[3] / "target" / "kernel-build-tests"
        fixture_root.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="kernel-build-test-", dir=fixture_root)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        source = self.root / "linux-6.18.49"
        (source / "scripts").mkdir(parents=True)
        symbols = set()
        for fragment in (SCRIPT.parent / "kconfig").rglob("*.config"):
            for line in fragment.read_text().splitlines():
                if line.startswith("CONFIG_") and "=" in line:
                    symbols.add(line.split("=", 1)[0])
        (source / "Kconfig").write_text(
            "".join(f"config {symbol.removeprefix('CONFIG_')}\n" for symbol in sorted(symbols))
        )
        self.executable(source / "scripts/config", '''#!/usr/bin/env python3
import pathlib, sys
path = pathlib.Path('.config')
mode, key, *value = sys.argv[1:]
old = [line for line in path.read_text().splitlines()
       if not line.startswith(key + '=') and line != '# ' + key + ' is not set']
if mode == '--enable': line = key + '=y'
elif mode == '--disable': line = '# ' + key + ' is not set'
elif mode == '--set-str': line = key + '="' + value[0] + '"'
else: line = key + '=' + value[0]
path.write_text('\\n'.join(old + [line]) + '\\n')
''')
        cache = self.root / "cache" / "src"
        cache.mkdir(parents=True)
        tarball = cache / "linux-6.18.49.tar.xz"
        with tarfile.open(tarball, "w:xz") as archive:
            archive.add(source, arcname=source.name)
        self.executable(self.bin / "make", '''#!/usr/bin/env python3
import os, pathlib, sys
command = sys.argv[-1]
if command == 'defconfig': pathlib.Path('.config').write_text('')
if command == 'olddefconfig' and os.environ.get('TEST_MODULE'):
    p = pathlib.Path('.config')
    p.write_text(p.read_text().replace('CONFIG_SECCOMP=y', 'CONFIG_SECCOMP=m'))
if command == 'bzImage':
    counter = pathlib.Path('../compilations')
    count = int(counter.read_text()) + 1 if counter.exists() else 1
    counter.write_text(str(count))
    output = pathlib.Path('arch/x86/boot/bzImage')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text('test-kernel-' + str(count))
''')
        self.executable(self.bin / "ccache", "#!/bin/sh\nexit 0\n")
        self.env = {
            "PATH": str(self.bin) + ":" + os.defpath,
            "HOME": str(self.root),
            "CARGO_UNIKERNEL_ASLR_DISABLED": "1",
            "CARGO_UNIKERNEL_KERNEL_VERSION": "6.18.49",
            "CARGO_UNIKERNEL_KERNEL_SHA256": hashlib.sha256(tarball.read_bytes()).hexdigest(),
            "CARGO_UNIKERNEL_KERNEL_CACHE_DIR": str(self.root / "cache"),
        }

    @staticmethod
    def executable(path, contents):
        path.write_text(contents)
        path.chmod(0o755)

    def run_build(self, *arguments, extra=None):
        return subprocess.run(
            ["bash", str(SCRIPT), *arguments], cwd=self.root,
            env=self.env | (extra or {}), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
        )

    def test_cache_is_verified_and_config_only_never_compiles(self):
        result = self.run_build("--config-only")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.root / "compilations").exists())
        for expected in ["test-kernel-1", "test-kernel-1"]:
            result = self.run_build()
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual((self.root / "linux-kernel/arch/x86/boot/bzImage").read_text(), expected)
        cached = next((self.root / "cache/bzimage").glob("*/bzImage"))
        cached.write_text("corrupted")
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual((self.root / "compilations").read_text(), "2")
        cached.with_name("config").unlink()
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual((self.root / "compilations").read_text(), "3")

    def test_missing_fragment_invalid_key_and_module_fail_closed(self):
        fragment = self.root / "extra.config"
        override = {"CARGO_UNIKERNEL_EXTRA_KCONFIG_FILE": str(fragment)}
        result = self.run_build(extra=override)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing or unreadable", result.stdout)
        fragment.write_text("NOT_A_CONFIG_KEY=enable\n")
        result = self.run_build(extra=override)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Kconfig key", result.stdout)
        fragment.write_text("CONFIG_DOES_NOT_EXIST=disable\n")
        result = self.run_build(extra=override)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no such symbol", result.stdout)
        result = self.run_build(extra={"TEST_MODULE": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CONFIG_SECCOMP=m", result.stdout)
        self.assertFalse((self.root / "compilations").exists())

    def test_build_flags_change_the_cache_key(self):
        for flags in ["", "-fno-inline"]:
            result = self.run_build(extra={"KCFLAGS": flags})
            self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual((self.root / "compilations").read_text(), "2")

    def test_bad_checksum_and_path_like_version_are_rejected(self):
        for override in [
            {"CARGO_UNIKERNEL_KERNEL_VERSION": "../../outside"},
            {"CARGO_UNIKERNEL_KERNEL_SHA256": "bad"},
            {"CARGO_UNIKERNEL_KERNEL_SHA256": "0" * 64},
        ]:
            result = self.run_build(extra=override)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.root / "compilations").exists())


if __name__ == "__main__":
    unittest.main()
