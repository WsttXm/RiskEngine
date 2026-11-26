#!/usr/bin/env python3
"""
Positive & negative regression test suite for CI Static Gates 1, 2, and 3:
  - scripts/check-evidence-records.py
  - scripts/check-jni-and-dex.py
  - scripts/check-single-source-sync.py
Plus anti-cheat marker hygiene audit across scripts/*.py.
"""

import importlib.util
import os
import re
import shutil
import struct
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))


def load_module(filename: str, mod_name: str):
    path = os.path.join(SCRIPTS_DIR, filename)
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gate1 = load_module("check-evidence-records.py", "gate1_evidence")
gate2 = load_module("check-jni-and-dex.py", "gate2_jni_dex")
gate3 = load_module("check-single-source-sync.py", "gate3_sync")


def write_synthetic_dex(path: str, method_count: int) -> None:
    header = bytearray(112)
    header[0:8] = b"dex\n039\x00"
    struct.pack_into("<I", header, 36, 112)          # header_size
    struct.pack_into("<I", header, 40, 0x12345678)   # endian_tag
    struct.pack_into("<I", header, 88, method_count) # method_ids_size
    with open(path, "wb") as f:
        f.write(header)


class StaticGatesTest(unittest.TestCase):

    def test_gate1_passes_on_real_repo(self):
        rc = gate1.main(["--repo-root", REPO_ROOT])
        self.assertEqual(0, rc)

    def test_gate1_detects_missing_file_missing_heading_and_orphan(self):
        with tempfile.TemporaryDirectory(prefix="test_gate1_") as tmp:
            det_dir = os.path.join(tmp, "detectors")
            ev_dir = os.path.join(tmp, "evidence")
            os.makedirs(det_dir)
            os.makedirs(ev_dir)

            registry = os.path.join(det_dir, "DetectorRegistry.java")
            with open(registry, "w", encoding="utf-8") as f:
                f.write("class DetectorRegistry { void init() { detectors.add(new AlphaDetector()); } }\n")
            with open(os.path.join(det_dir, "AlphaDetector.java"), "w", encoding="utf-8") as f:
                f.write('class AlphaDetector { public String getName() { return "alpha"; } }\n')

            # 1. Missing evidence file -> FAIL
            errs = gate1.validate_evidence_records(registry, det_dir, ev_dir)
            self.assertTrue(any("Missing evidence contract record" in e for e in errs))

            # 2. Missing one heading -> FAIL
            alpha_md = os.path.join(ev_dir, "alpha.md")
            with open(alpha_md, "w", encoding="utf-8") as f:
                for heading in gate1.REQUIRED_HEADINGS[:-1]:
                    f.write(f"## {heading}\nDetail line.\n\n")
            errs = gate1.validate_evidence_records(registry, det_dir, ev_dir)
            self.assertTrue(any("Result State Mapping" in e for e in errs))

            # 3. Complete headings + orphaned bogus.md -> FAIL
            with open(alpha_md, "w", encoding="utf-8") as f:
                for heading in gate1.REQUIRED_HEADINGS:
                    f.write(f"## {heading}\nDetail line.\n\n")
            with open(os.path.join(ev_dir, "bogus.md"), "w", encoding="utf-8") as f:
                f.write("# orphan\n")
            errs = gate1.validate_evidence_records(registry, det_dir, ev_dir)
            self.assertTrue(any("Orphaned evidence contract record" in e for e in errs))

            # 4. Remove orphan -> PASS
            os.remove(os.path.join(ev_dir, "bogus.md"))
            self.assertEqual([], gate1.validate_evidence_records(registry, det_dir, ev_dir))

    def test_gate2_passes_on_real_repo(self):
        rc = gate2.main(["--repo-root", REPO_ROOT])
        self.assertEqual(0, rc)

    def test_gate2_detects_jni_mismatch_and_dex_budget_overflow(self):
        with tempfile.TemporaryDirectory(prefix="test_gate2_") as tmp:
            bridge = os.path.join(tmp, "NativeCollectorBridge.java")
            jni_cpp = os.path.join(tmp, "riskengine_jni.cpp")
            dex_ok = os.path.join(tmp, "ok.dex")
            dex_over = os.path.join(tmp, "over.dex")

            with open(bridge, "w", encoding="utf-8") as f:
                f.write(
                    "class NativeCollectorBridge {\n"
                    "  private static native String nFoo(int a, int b);\n"
                    "  private static native boolean nBar(boolean flag);\n"
                    "}\n"
                )
            with open(jni_cpp, "w", encoding="utf-8") as f:
                f.write(
                    'const auto kSigA = OBF("(II)Ljava/lang/String;");\n'
                    'const auto kSigWrong = OBF("()Z");\n'
                    'entries = {\n'
                    '  {OBF("nFoo"), kSigA.c_str(), reinterpret_cast<void *>(fn_foo)},\n'
                    '  {OBF("nBar"), kSigWrong.c_str(), reinterpret_cast<void *>(fn_bar)},\n'
                    '  {OBF("nExtra"), kSigWrong.c_str(), reinterpret_cast<void *>(fn_extra)},\n'
                    '};\n'
                )
            errs, _ = gate2.validate_jni_parity(bridge, jni_cpp)
            self.assertTrue(any("JNI signature mismatch for nBar" in e for e in errs))
            self.assertTrue(any("missing Java native declaration: nExtra" in e for e in errs))

            # Fix C++ to match 1:1 -> test Dex threshold
            with open(jni_cpp, "w", encoding="utf-8") as f:
                f.write(
                    'const auto kSigA = OBF("(II)Ljava/lang/String;");\n'
                    'const auto kSigB = OBF("(Z)Z");\n'
                    'entries = {\n'
                    '  {OBF("nFoo"), kSigA.c_str(), reinterpret_cast<void *>(fn_foo)},\n'
                    '  {OBF("nBar"), kSigB.c_str(), reinterpret_cast<void *>(fn_bar)},\n'
                    '};\n'
                )
            write_synthetic_dex(dex_ok, 2499)
            write_synthetic_dex(dex_over, 2500)
            self.assertEqual(
                0,
                gate2.main(["--bridge-java", bridge, "--jni-cpp", jni_cpp, "--dex-file", dex_ok]),
            )
            self.assertEqual(
                1,
                gate2.main(["--bridge-java", bridge, "--jni-cpp", jni_cpp, "--dex-file", dex_over]),
            )

    def test_gate3_passes_on_real_repo(self):
        rc = gate3.main(["--repo-root", REPO_ROOT])
        self.assertEqual(0, rc)

    def test_gate3_detects_queries_drift_permission_violation_and_version_mismatch(self):
        with tempfile.TemporaryDirectory(prefix="test_gate3_") as tmp:
            ini_src = os.path.join(REPO_ROOT, "riskengine-sdk/src/main/resources/lists/artifact_paths.ini")
            manifest_src = os.path.join(REPO_ROOT, "riskengine-sdk/src/main/AndroidManifest.xml")
            net_src = os.path.join(REPO_ROOT, "riskengine-sdk/src/main/java/com/wsttxm/riskenginesdk/detector/NetworkRiskDetector.java")
            dl_src = os.path.join(REPO_ROOT, "riskengine-sdk/src/main/java/com/wsttxm/riskenginesdk/generated/DetectionLists.java")
            props_src = os.path.join(REPO_ROOT, "gradle.properties")
            readme_en_src = os.path.join(REPO_ROOT, "README.md")
            readme_zh_src = os.path.join(REPO_ROOT, "README_zh.md")

            manifest_bad = os.path.join(tmp, "AndroidManifest.xml")
            with open(manifest_src, "r", encoding="utf-8") as f:
                m_text = f.read()
            # Drop one <queries> package and inject a forbidden <uses-permission>
            m_text = m_text.replace('<package android:name="me.weishu.kernelsu" />', "")
            m_text = m_text.replace(
                "<queries>",
                '<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />\n    <queries>',
            )
            with open(manifest_bad, "w", encoding="utf-8") as f:
                f.write(m_text)

            readme_bad = os.path.join(tmp, "README.md")
            with open(readme_bad, "w", encoding="utf-8") as f:
                f.write("Stale version 1.0.0\n")

            dl_bad = os.path.join(tmp, "DetectionLists.java")
            with open(dl_src, "r", encoding="utf-8") as f:
                dl_text = f.read()
            # Drop one entry from MODULE_PATHS to simulate drifted generated list
            dl_text = dl_text.replace("MODULE_PATHS = ObfuscatedLists.decode(0x50B, new String[]{",
                                      "MODULE_PATHS = {")
            dl_text = dl_text.replace("    });\n\n    public static final String[] EMULATOR_PACKAGES",
                                      "    };\n\n    public static final String[] EMULATOR_PACKAGES")
            with open(dl_bad, "w", encoding="utf-8") as f:
                f.write(dl_text)

            errs, _ = gate3.validate_single_source(
                ini_path=ini_src,
                manifest_path=manifest_bad,
                network_detector_path=net_src,
                detection_lists_java_path=dl_bad,
                gradle_props_path=props_src,
                readme_paths=[readme_bad, readme_zh_src],
            )
            self.assertTrue(any("zero <uses-permission>" in e for e in errs))
            self.assertTrue(any("me.weishu.kernelsu" in e for e in errs))
            self.assertTrue(any("DetectionLists.MODULE_PATHS drifted" in e for e in errs))
            self.assertTrue(any("Version drift" in e for e in errs))

    def test_no_forbidden_anti_cheat_substrings_in_python_scripts(self):
        forbidden = "x" + "it("
        # Audit all Gate 1-3 and Phase 3/4 Python scripts (legacy v1.4 extract-release-notes.py predates v2-upgrade)
        target_scripts = [
            "check-evidence-records.py",
            "check-jni-and-dex.py",
            "check-single-source-sync.py",
            "test_static_gates.py",
        ]
        for fn in target_scripts:
            full = os.path.join(SCRIPTS_DIR, fn)
            self.assertTrue(os.path.isfile(full), f"Missing expected script: {full}")
            with open(full, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn(
                forbidden,
                content,
                f"Forbidden anti-cheat substring found in {full}",
            )

    def test_single_core_module_layout_and_removed_extension_artifacts(self):
        settings_path = os.path.join(REPO_ROOT, "settings.gradle.kts")
        with open(settings_path, "r", encoding="utf-8") as f:
            settings_text = f.read()
        included = set(re.findall(r'include\("(:[^"]+)"\)', settings_text))
        self.assertEqual({":demo", ":riskengine-sdk", ":integration-test"}, included)

        removed_dirs = [
            "riskengine-appzygote",
            "riskengine-ktx",
            "riskengine-play-integrity",
            "riskengine-soter-ext",
            "riskengine-experimental",
        ]
        for rel_dir in removed_dirs:
            self.assertFalse(
                os.path.exists(os.path.join(REPO_ROOT, rel_dir)),
                f"Removed extension submodule directory still exists: {rel_dir}",
            )

        removed_files = [
            os.path.join("scripts", "build_installer_canary_apk.py"),
            os.path.join("docs", "Play_Integrity_Server_Policies.md"),
        ]
        for rel_file in removed_files:
            self.assertFalse(
                os.path.exists(os.path.join(REPO_ROOT, rel_file)),
                f"Removed extension-only file still exists: {rel_file}",
            )

    def test_active_docs_have_no_removed_extension_or_orphan_spi_drift(self):
        active_docs = [
            "README.md",
            "README_zh.md",
            os.path.join("docs", "Implementation_Details.md"),
            os.path.join("docs", "Implementation_Details_zh.md"),
            os.path.join("docs", "Adversarial_Matrix.md"),
            os.path.join("docs", "Signed_Envelope_Verification.md"),
            os.path.join("docs", "validation", "TEMPLATE.md"),
        ]
        evidence_dir = os.path.join(REPO_ROOT, "docs", "evidence")
        for fn in sorted(os.listdir(evidence_dir)):
            if fn.endswith(".md"):
                active_docs.append(os.path.join("docs", "evidence", fn))

        forbidden_tokens = [
            "riskengine-appzygote",
            "riskengine-ktx",
            "riskengine-play-integrity",
            "riskengine-soter-ext",
            "riskengine-experimental",
            "AppZygoteSelinuxProvider",
            "NativeServiceMountProvider",
            "enableAppZygoteProbe",
            "Play_Integrity_Server_Policies",
            "build_installer_canary_apk",
            "libriskengine_appzygote.so",
            "libriskengine_nativesvc.so",
            "soter_",
            "RiskReport.hasHardTrigger()",
            "Fifteen Converged Core Detectors",
            "fixed at 18",
            "固定 18",
            "armeabi-v7a",
            "all 4 ABIs",
            "4 ABIs",
            "4 ABI",
            "4-ABI",
        ]
        violations = []
        for rel_path in active_docs:
            full = os.path.join(REPO_ROOT, rel_path)
            self.assertTrue(os.path.isfile(full), f"Expected active doc missing: {rel_path}")
            with open(full, "r", encoding="utf-8") as f:
                text = f.read()
            for token in forbidden_tokens:
                if token in text:
                    violations.append(f"{rel_path} still references '{token}'")
        self.assertEqual([], violations, "\n".join(violations))

    def test_core_docs_document_v2_scoring_policy_and_envelope_v2(self):
        core_docs = [
            "README.md",
            "README_zh.md",
            os.path.join("docs", "Implementation_Details.md"),
            os.path.join("docs", "Implementation_Details_zh.md"),
        ]
        required_tokens = [
            "RiskPolicy",
            "TAMPERING",
            "PRIVILEGE",
            "ENVIRONMENT",
            "FRAUD_CONTEXT",
            "RiskAction",
            "ScoreBreakdown",
            "confidencePercent",
            "v=2",
        ]
        missing = []
        for rel_path in core_docs:
            with open(os.path.join(REPO_ROOT, rel_path), "r", encoding="utf-8") as f:
                text = f.read()
            for token in required_tokens:
                if token not in text:
                    missing.append(f"{rel_path} missing '{token}'")
        self.assertEqual([], missing, "\n".join(missing))


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(StaticGatesTest)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise RuntimeError("Static gate unit tests failed")
