#!/usr/bin/env python3
"""
Unit tests for CI Static Gates 4 & 5:
  - scripts/check-public-api.py (Public ABI lock + AAR/POM purity)
  - scripts/check-boundary-guards.py (Reflection allowlist + UI text boundary)

Proves both positive PASS against the real repository and negative FAIL on
synthetic broken fixtures (breaking ABI change, 3rd-party/UI class in AAR,
POM runtime dependency, unregistered reflection, allowlist count drift,
blocked hidden-API reflection in threat probe, and UI text branching).
"""

import importlib.util
import io
import os
import sys
import tempfile
import unittest
import zipfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def load_module(script_name: str, module_name: str):
    path = os.path.join(REPO_ROOT, "scripts", script_name)
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


GATE4 = load_module("check-public-api.py", "check_public_api")
GATE5 = load_module("check-boundary-guards.py", "check_boundary_guards")


def clone_aar_with_extra_class(src_aar: str, dst_aar: str, extra_jar_entry: str = "", r_txt_override: str = None):
    with zipfile.ZipFile(src_aar, "r") as zin, zipfile.ZipFile(dst_aar, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "classes.jar" and extra_jar_entry:
                buf = io.BytesIO()
                with zipfile.ZipFile(io.BytesIO(data), "r") as jzin, zipfile.ZipFile(buf, "w") as jzout:
                    for jitem in jzin.infolist():
                        jzout.writestr(jitem, jzin.read(jitem.filename))
                    jzout.writestr(extra_jar_entry, b"\xca\xfe\xba\xbe")
                data = buf.getvalue()
            elif item.filename == "R.txt" and r_txt_override is not None:
                data = r_txt_override.encode("utf-8")
            zout.writestr(item, data)


class Gate4PublicApiTests(unittest.TestCase):
    def setUp(self):
        self.aar = os.path.join(
            REPO_ROOT, "riskengine-sdk", "build", "outputs", "aar", "riskengine-sdk-release.aar"
        )
        self.pom = os.path.join(
            REPO_ROOT, "riskengine-sdk", "build", "publications", "release", "pom-default.xml"
        )
        self.api_file = os.path.join(
            REPO_ROOT, "riskengine-sdk", "api", "riskengine-sdk.api"
        )

    def test_real_repo_passes(self):
        errors, summary = GATE4.run_gate(
            mode="check",
            aar_path=self.aar,
            api_file=self.api_file,
            pom_path=self.pom,
            check_pom=True,
        )
        self.assertEqual([], errors)
        self.assertIn("public/protected types locked", summary)

    def test_public_abi_contains_no_orphan_extension_spis(self):
        with open(self.api_file, "r", encoding="utf-8") as f:
            api_text = f.read()
        forbidden_symbols = [
            "AppZygoteSelinuxProvider",
            "NativeServiceMountProvider",
            "enableAppZygoteProbe",
            "isEnableAppZygoteProbe",
            "AppZygoteDirtyPolicyResult",
            "probeAppZygote",
            "evaluateAppZygoteSnapshot",
        ]
        for sym in forbidden_symbols:
            self.assertNotIn(
                sym,
                api_text,
                f"Orphan extension SPI symbol '{sym}' must not appear in locked public ABI",
            )

    def test_breaking_api_signature_fails(self):
        with tempfile.TemporaryDirectory() as td:
            broken_api = os.path.join(td, "broken.api")
            with open(self.api_file, "r", encoding="utf-8") as f:
                content = f.read()
            # Mutate a real public method signature to simulate an ABI break.
            mutated = content.replace("collectSync(", "collectSyncBroken(", 1)
            self.assertNotEqual(content, mutated)
            with open(broken_api, "w", encoding="utf-8") as f:
                f.write(mutated)

            errors, _ = GATE4.run_gate(
                mode="check",
                aar_path=self.aar,
                api_file=broken_api,
                pom_path=self.pom,
                check_pom=True,
            )
            self.assertTrue(errors)
            self.assertIn("Public ABI mismatch", errors[0])

    def test_third_party_or_ui_class_in_aar_fails(self):
        with tempfile.TemporaryDirectory() as td:
            bad_aar = os.path.join(td, "bad.aar")
            clone_aar_with_extra_class(
                self.aar, bad_aar, extra_jar_entry="androidx/appcompat/FakeUi.class"
            )
            errors = GATE4.audit_aar_purity(bad_aar)
            self.assertTrue(errors)
            self.assertTrue(any("androidx/appcompat/FakeUi.class" in e for e in errors))

    def test_non_empty_r_txt_fails(self):
        with tempfile.TemporaryDirectory() as td:
            bad_aar = os.path.join(td, "bad_r.aar")
            clone_aar_with_extra_class(
                self.aar, bad_aar, r_txt_override="int string app_name 0x7f010001\n"
            )
            errors = GATE4.audit_aar_purity(bad_aar)
            self.assertTrue(errors)
            self.assertTrue(any("R.txt" in e for e in errors))

    def test_pom_with_runtime_dependency_fails(self):
        with tempfile.TemporaryDirectory() as td:
            bad_pom = os.path.join(td, "pom-default.xml")
            with open(bad_pom, "w", encoding="utf-8") as f:
                f.write(
                    '<?xml version="1.0" encoding="UTF-8"?>\n'
                    '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
                    "  <groupId>com.wsttxm</groupId>\n"
                    "  <artifactId>riskengine-sdk</artifactId>\n"
                    "  <packaging>aar</packaging>\n"
                    "  <dependencies>\n"
                    "    <dependency>\n"
                    "      <groupId>com.squareup.okhttp3</groupId>\n"
                    "      <artifactId>okhttp</artifactId>\n"
                    "      <version>4.12.0</version>\n"
                    "    </dependency>\n"
                    "  </dependencies>\n"
                    "</project>\n"
                )
            errors = GATE4.audit_pom_purity(bad_pom)
            self.assertTrue(errors)
            self.assertTrue(any("0 runtime dependencies" in e for e in errors))

    def test_javap_parser_handles_annotations_and_package_private_ui_headers(self):
        sample = (
            'Compiled from "Sample.java"\n'
            'public @interface com.wsttxm.riskenginesdk.MyAnnotation {\n'
            '  public abstract java.lang.String value();\n'
            '}\n'
            'class com.wsttxm.riskenginesdk.InternalActivity extends android.app.Activity {\n'
            '  com.wsttxm.riskenginesdk.InternalActivity();\n'
            '}\n'
        )
        blocks, headers = GATE4.parse_javap_blocks(sample)
        self.assertIn("com.wsttxm.riskenginesdk.MyAnnotation", blocks)
        self.assertNotIn("com.wsttxm.riskenginesdk.InternalActivity", blocks)
        self.assertTrue(any("android.app.Activity" in h for h in headers))


class Gate5BoundaryGuardTests(unittest.TestCase):
    def test_real_repo_passes(self):
        java_root = os.path.join(REPO_ROOT, "riskengine-sdk", "src", "main", "java")
        cpp_root = os.path.join(REPO_ROOT, "riskengine-sdk", "src", "main", "cpp")
        errors, stats = GATE5.audit_core_boundaries(java_root, cpp_root)
        self.assertEqual([], errors)
        self.assertGreater(stats["java_files"], 50)
        self.assertGreater(stats["cpp_files"], 20)
        self.assertGreater(stats["reflection_sites"], 0)

    def test_unregistered_reflection_fails(self):
        with tempfile.TemporaryDirectory() as td:
            jroot = os.path.join(td, "java")
            croot = os.path.join(td, "cpp")
            os.makedirs(os.path.join(jroot, "com", "wsttxm", "riskenginesdk"), exist_ok=True)
            os.makedirs(croot, exist_ok=True)
            with open(
                os.path.join(jroot, "com", "wsttxm", "riskenginesdk", "Sneaky.java"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write(
                    "package com.wsttxm.riskenginesdk;\n"
                    "public class Sneaky {\n"
                    "  void f() { try { Class.forName(\"android.os.Hidden\"); } catch (Exception e) {} }\n"
                    "}\n"
                )
            errors, _ = GATE5.audit_core_boundaries(jroot, croot, allowlist={})
            self.assertTrue(errors)
            self.assertTrue(any("Unregistered reflection 'Class.forName'" in e for e in errors))

    def test_reflection_count_drift_fails(self):
        with tempfile.TemporaryDirectory() as td:
            jroot = os.path.join(td, "java")
            croot = os.path.join(td, "cpp")
            os.makedirs(os.path.join(jroot, "com", "wsttxm", "riskenginesdk"), exist_ok=True)
            os.makedirs(croot, exist_ok=True)
            with open(
                os.path.join(jroot, "com", "wsttxm", "riskenginesdk", "Allowed.java"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write(
                    "package com.wsttxm.riskenginesdk;\n"
                    "public class Allowed {\n"
                    "  void f() {\n"
                    "    try {\n"
                    "      Class.forName(\"a.B\");\n"
                    "      Class.forName(\"c.D\");\n"
                    "    } catch (Exception e) {}\n"
                    "  }\n"
                    "}\n"
                )
            allow = {
                ("com/wsttxm/riskenginesdk/Allowed.java", "Class.forName"): {
                    "count": 1,
                    "target": "a.B",
                    "degradation_strategy": "Catches Exception and degrades.",
                }
            }
            errors, _ = GATE5.audit_core_boundaries(jroot, croot, allowlist=allow)
            self.assertTrue(errors)
            self.assertTrue(any("Reflection count drift" in e for e in errors))

    def test_blocked_hidden_api_in_threat_probe_fails(self):
        with tempfile.TemporaryDirectory() as td:
            jroot = os.path.join(td, "java")
            croot = os.path.join(td, "cpp")
            pdir = os.path.join(
                jroot, "com", "wsttxm", "riskenginesdk", "detector", "probe", "threat"
            )
            os.makedirs(pdir, exist_ok=True)
            os.makedirs(croot, exist_ok=True)
            with open(os.path.join(pdir, "BadThreatProbe.java"), "w", encoding="utf-8") as f:
                f.write(
                    "package com.wsttxm.riskenginesdk.detector.probe.threat;\n"
                    "public class BadThreatProbe {\n"
                    "  void f() { try { Class.forName(\"android.permission.IPermissionManager\"); } catch (Exception e) {} }\n"
                    "}\n"
                )
            errors, _ = GATE5.audit_core_boundaries(jroot, croot, allowlist={})
            self.assertTrue(any("Blocked hidden-API reference" in e for e in errors))

    def test_ui_text_branching_in_java_and_cpp_fails(self):
        with tempfile.TemporaryDirectory() as td:
            jroot = os.path.join(td, "java")
            croot = os.path.join(td, "cpp")
            os.makedirs(os.path.join(jroot, "com", "wsttxm", "riskenginesdk"), exist_ok=True)
            os.makedirs(croot, exist_ok=True)
            with open(
                os.path.join(jroot, "com", "wsttxm", "riskenginesdk", "UiLeak.java"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write(
                    "package com.wsttxm.riskenginesdk;\n"
                    "public class UiLeak {\n"
                    "  boolean bad(RiskReport r) { return r.getSummary().contains(\"High Risk\"); }\n"
                    "}\n"
                )
            with open(os.path.join(croot, "bad_probe.cpp"), "w", encoding="utf-8") as f:
                f.write(
                    '#include <string>\n'
                    'bool bad(const std::string &s) { return s.find("高风险") != std::string::npos; }\n'
                )
            errors, _ = GATE5.audit_core_boundaries(jroot, croot, allowlist={})
            self.assertTrue(any("branches on UI display text" in e for e in errors))
            self.assertTrue(any("Core C++ source" in e for e in errors))

    def test_commented_reflection_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            jroot = os.path.join(td, "java")
            croot = os.path.join(td, "cpp")
            os.makedirs(os.path.join(jroot, "com", "wsttxm", "riskenginesdk"), exist_ok=True)
            os.makedirs(croot, exist_ok=True)
            with open(
                os.path.join(jroot, "com", "wsttxm", "riskenginesdk", "DocOnly.java"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write(
                    "package com.wsttxm.riskenginesdk;\n"
                    "// Never call Class.forName(\"foo\") or getSummary().contains(\"High Risk\") here.\n"
                    "/* Also avoid getDeclaredMethod(\"bar\") */\n"
                    "public class DocOnly {}\n"
                )
            errors, _ = GATE5.audit_core_boundaries(jroot, croot, allowlist={})
            self.assertEqual([], errors)

    def test_cpp_digit_separator_does_not_corrupt_comment_stripping(self):
        with tempfile.TemporaryDirectory() as td:
            jroot = os.path.join(td, "java")
            croot = os.path.join(td, "cpp")
            os.makedirs(jroot, exist_ok=True)
            os.makedirs(croot, exist_ok=True)
            with open(os.path.join(croot, "digit_sep.cpp"), "w", encoding="utf-8") as f:
                f.write(
                    "constexpr int kDelayMs = 10'000;\n"
                    "// 中文注释提及 sanitize_maps_path 与 高风险 必须被正常剥离\n"
                    "constexpr unsigned kMask = 0xFF'00;\n"
                    "int ok() { return kDelayMs + static_cast<int>(kMask); }\n"
                )
            errors, _ = GATE5.audit_core_boundaries(jroot, croot, allowlist={})
            self.assertEqual([], errors)

    def test_multiline_reflection_and_text_branching_fail(self):
        with tempfile.TemporaryDirectory() as td:
            jroot = os.path.join(td, "java")
            croot = os.path.join(td, "cpp")
            pdir = os.path.join(
                jroot, "com", "wsttxm", "riskenginesdk", "detector", "probe", "threat"
            )
            os.makedirs(pdir, exist_ok=True)
            os.makedirs(croot, exist_ok=True)
            with open(os.path.join(pdir, "MultilineSneaky.java"), "w", encoding="utf-8") as f:
                f.write(
                    "package com.wsttxm.riskenginesdk.detector.probe.threat;\n"
                    "public class MultilineSneaky {\n"
                    "  void f(Object pm, RiskReport r) {\n"
                    "    try {\n"
                    "      Class\n"
                    "        .forName(\n"
                    "          \"android.permission.IPermissionManager\"\n"
                    "        );\n"
                    "      pm.getClass()\n"
                    "        .getMethod(\"getPackageInfoAsUser\", String.class);\n"
                    "      if (r.getSummary()\n"
                    "          .contains(\"High Risk\")) {\n"
                    "      }\n"
                    "    } catch (Exception e) {}\n"
                    "  }\n"
                    "}\n"
                )
            errors, _ = GATE5.audit_core_boundaries(jroot, croot, allowlist={})
            self.assertTrue(any("Unregistered reflection 'Class.forName'" in e for e in errors))
            self.assertTrue(any("Unregistered reflection 'getMethod'" in e for e in errors))
            self.assertTrue(any("Blocked hidden-API reference" in e for e in errors))
            self.assertTrue(any("branches on UI display text" in e for e in errors))


def main() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    if main() != 0:
        raise RuntimeError("API and boundary gate unit tests failed")
