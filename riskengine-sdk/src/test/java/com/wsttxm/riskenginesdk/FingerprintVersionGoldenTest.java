package com.wsttxm.riskenginesdk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import com.wsttxm.riskenginesdk.core.FingerprintIdBuilder;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.FingerprintId;
import com.wsttxm.riskenginesdk.util.CpuInfoParser;

import org.junit.Test;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class FingerprintVersionGoldenTest {

    private static final String GOLDEN_SALT = "golden-salt-2026";
    private static final String EXPECTED_V1_HW =
            "806329abbbb211d71e8326654f40722936e9474824c581bc20a0d2fae7af1805";
    private static final String EXPECTED_V1_SYS =
            "078774d87a4ec4ecf823556cc38979ac630f321bcbfa9d501ef0f29c5761907d";
    private static final String EXPECTED_V1_VOL =
            "81fedd242f4ed7141a4394a1cbd64520126953353b43e6358decff5913706de0";
    private static final String EXPECTED_V1_COMPOSITE =
            "87884072343ff4618c2fa3b57a9a7aa6e7cb8757f363fe750a6612b9b5767108";
    private static final String EXPECTED_V1_GPU_BUCKET = "ba4531d61786b8f5";

    @Test
    public void legacyTwoArgBuildAndV1MatchPhase0GoldenSha256BitForBit() {
        DeviceFingerprint fp = buildGoldenFingerprint();

        FingerprintId legacy = FingerprintIdBuilder.build(fp, GOLDEN_SALT);
        FingerprintId explicitV1 = FingerprintIdBuilder.build(
                fp, GOLDEN_SALT, FingerprintVersion.V1,
                FingerprintStability.OPTIMAL, FingerprintHasher.SHA256);

        assertEquals(EXPECTED_V1_HW, legacy.getHardwareId());
        assertEquals(EXPECTED_V1_SYS, legacy.getSystemId());
        assertEquals(EXPECTED_V1_VOL, legacy.getVolatileId());
        assertEquals(EXPECTED_V1_COMPOSITE, legacy.getCompositeId());
        assertEquals(EXPECTED_V1_GPU_BUCKET, legacy.getHardwareBucketDigests().get("gpu"));
        assertEquals(FingerprintVersion.V1, legacy.getVersion());
        assertEquals(64, legacy.getSystemId().length());

        assertEquals(legacy.getHardwareId(), explicitV1.getHardwareId());
        assertEquals(legacy.getSystemId(), explicitV1.getSystemId());
        assertEquals(legacy.getVolatileId(), explicitV1.getVolatileId());
        assertEquals(legacy.getCompositeId(), explicitV1.getCompositeId());
        assertEquals(legacy.getHardwareBucketDigests(), explicitV1.getHardwareBucketDigests());
    }

    @Test
    public void identityHasherLocksV1AndV2CanonicalInputs() {
        DeviceFingerprint fp = new DeviceFingerprint();
        CollectorResult gpu = new CollectorResult("gpu_info");
        gpu.addValue("vendor", "Qualcomm");
        fp.addResult(gpu);

        CollectorResult build = new CollectorResult("build_props");
        build.addValue("fingerprint", "fp-1");
        fp.addResult(build);

        CollectorResult codec = new CollectorResult("codec_info");
        codec.addValue("codec_matrix_hash", "codec-h1");
        fp.addResult(codec);

        CollectorResult aid = new CollectorResult("android_id");
        aid.addValue("settings_api", "aid-1");
        fp.addResult(aid);

        FingerprintHasher identity = s -> s;

        FingerprintId v1 = FingerprintIdBuilder.build(
                fp, "s", FingerprintVersion.V1, FingerprintStability.OPTIMAL, identity);
        assertEquals("s|hw|gpu_info.vendor=Qualcomm", v1.getHardwareId());
        assertEquals("s|sys|build_props.fingerprint=fp-1", v1.getSystemId());
        assertEquals("s|vol|android_id.settings_api=aid-1", v1.getVolatileId());
        assertEquals("s|composite|s|hw|gpu_info.vendor=Qualcomm|s|sys|build_props.fingerprint=fp-1",
                v1.getCompositeId());

        FingerprintId v2Stable = FingerprintIdBuilder.build(
                fp, "s", FingerprintVersion.V2, FingerprintStability.STABLE, identity);
        assertEquals("s|v2|hw|gpu_info.vendor=Qualcomm", v2Stable.getHardwareId());
        assertEquals("", v2Stable.getSystemId());
        assertEquals("", v2Stable.getVolatileId());
        assertEquals("s|v2|composite|STABLE|s|v2|hw|gpu_info.vendor=Qualcomm",
                v2Stable.getCompositeId());

        FingerprintId v2Optimal = FingerprintIdBuilder.build(
                fp, "s", FingerprintVersion.V2, FingerprintStability.OPTIMAL, identity);
        assertEquals("s|v2|sys|build_props.fingerprint=fp-1\u001fcodec_info.codec_matrix_hash=codec-h1",
                v2Optimal.getSystemId());
        assertEquals("", v2Optimal.getVolatileId());
        assertEquals(
                "s|v2|composite|OPTIMAL|" + v2Optimal.getHardwareId() + "|" + v2Optimal.getSystemId(),
                v2Optimal.getCompositeId());

        FingerprintId v2Unique = FingerprintIdBuilder.build(
                fp, "s", FingerprintVersion.V2, FingerprintStability.UNIQUE, identity);
        assertEquals("s|v2|vol|android_id.settings_api=aid-1", v2Unique.getVolatileId());
        assertEquals(
                "s|v2|composite|UNIQUE|" + v2Unique.getHardwareId() + "|"
                        + v2Unique.getSystemId() + "|" + v2Unique.getVolatileId(),
                v2Unique.getCompositeId());
    }

    @Test
    public void sha256HasherUsesUtf8AndZeroPadded64CharHex() {
        String h1 = FingerprintHasher.SHA256.hash("设备指纹-α");
        String h2 = FingerprintHasher.SHA256.hash("设备指纹-β");
        assertEquals(64, h1.length());
        assertEquals(64, h2.length());
        assertNotEquals("UTF-8 hashing must preserve non-ASCII Unicode entropy", h1, h2);
        assertTrue(h1.matches("[0-9a-f]{64}"));
    }

    @Test
    public void cpuInfoParserStripsVolatileFieldsWhilePreservingFlagsAndModelName() {
        String sample1 = ""
                + "processor\t: 0\n"
                + "model name\t: Intel(R) Core(TM) i7-12700H\n"
                + "cpu MHz\t\t: 2300.125\n"
                + "BogoMIPS\t: 4600.00\n"
                + "flags\t\t: fpu vme de pse tsc msr pae avx2\n"
                + "\n"
                + "processor\t: 1\n"
                + "model name\t: Intel(R) Core(TM) i7-12700H\n"
                + "cpu MHz\t\t: 3150.500\n"
                + "BogoMIPS\t: 4600.00\n"
                + "flags\t\t: fpu vme de pse tsc msr pae avx2\n"
                + "\n"
                + "Hardware\t: Qualcomm Technologies, Inc SM8650\n";

        String sample2 = sample1
                .replace("2300.125", "1800.000")
                .replace("3150.500", "4100.750")
                .replace("4600.00", "4608.12");

        CpuInfoParser.ParsedCpuInfo parsed1 = CpuInfoParser.parse(sample1);
        CpuInfoParser.ParsedCpuInfo parsed2 = CpuInfoParser.parse(sample2);

        assertEquals(2, parsed1.getCoreCount());
        assertEquals("Intel(R) Core(TM) i7-12700H", parsed1.getModelName());
        assertEquals("Qualcomm Technologies, Inc SM8650", parsed1.getHardware());
        assertTrue(parsed1.getFlags().contains("avx2"));

        String stable1 = parsed1.toStableFingerprintString();
        String stable2 = parsed2.toStableFingerprintString();
        assertEquals("BogoMIPS and cpu MHz jitter must not alter stable CPU fingerprint",
                stable1, stable2);
        assertFalse(stable1.toLowerCase().contains("bogomips"));
        assertFalse(stable1.toLowerCase().contains("cpu mhz"));
        assertTrue(stable1.contains("flags=fpu vme de pse tsc msr pae avx2"));
        assertTrue(stable1.contains("model name=Intel(R) Core(TM) i7-12700H"));

        DeviceFingerprint fp1 = buildGoldenFingerprint();
        CollectorResult c1 = new CollectorResult("cpu_info");
        c1.addValue("raw", sample1);
        fp1.addResult(c1);

        DeviceFingerprint fp2 = buildGoldenFingerprint();
        CollectorResult c2 = new CollectorResult("cpu_info");
        c2.addValue("raw", sample2);
        fp2.addResult(c2);

        FingerprintId id1 = FingerprintIdBuilder.build(
                fp1, GOLDEN_SALT, FingerprintVersion.V2,
                FingerprintStability.OPTIMAL, FingerprintHasher.SHA256);
        FingerprintId id2 = FingerprintIdBuilder.build(
                fp2, GOLDEN_SALT, FingerprintVersion.V2,
                FingerprintStability.OPTIMAL, FingerprintHasher.SHA256);
        assertEquals(id1.getCompositeId(), id2.getCompositeId());
        assertEquals(id1.getSystemId(), id2.getSystemId());
    }

    @Test
    public void isHardwareLayerReliableRequiresCoverageAndAtLeastTwoCoreBuckets() {
        Map<String, String> twoCore = new LinkedHashMap<>();
        twoCore.put("gpu", "aaaa1111bbbb2222");
        twoCore.put("cpu", "cccc3333dddd4444");

        FingerprintId reliable = new FingerprintId(
                "comp", "hw", "sys", "vol",
                7, 13, 5, 11,
                Collections.emptyList(), twoCore);
        assertTrue(reliable.isHardwareLayerReliable());

        // 7/13 >= 50%, but only 1 core physical bucket (gpu) + non-core buckets -> NOT reliable
        Map<String, String> oneCore = new LinkedHashMap<>();
        oneCore.put("gpu", "aaaa1111bbbb2222");
        oneCore.put("camera", "eeee5555ffff6666");
        oneCore.put("memory_battery", "7777888899990000");
        FingerprintId onlyOneCore = new FingerprintId(
                "comp", "hw", "sys", "vol",
                7, 13, 5, 11,
                Collections.emptyList(), oneCore);
        assertEquals(1, onlyOneCore.getCorePhysicalBucketCount());
        assertFalse(onlyOneCore.isHardwareLayerReliable());

        // 2 core buckets but coverage < 50% (6/13 = 46%) -> NOT reliable
        FingerprintId lowCoverage = new FingerprintId(
                "comp", "hw", "sys", "vol",
                6, 13, 5, 11,
                Collections.emptyList(), twoCore);
        assertFalse(lowCoverage.isHardwareLayerReliable());
    }

    @Test
    @SuppressWarnings("deprecation")
    public void configFingerprintDefaultsAndOverridesWork() {
        RiskEngineConfig def = new RiskEngineConfig.Builder().build();
        assertEquals(FingerprintVersion.V2, def.getFingerprintVersion());
        assertEquals(FingerprintStability.OPTIMAL, def.getFingerprintStability());
        assertEquals(FingerprintHasher.SHA256, def.getFingerprintHasher());

        FingerprintHasher customHasher = s -> "custom:" + s.length();
        RiskEngineConfig custom = new RiskEngineConfig.Builder()
                .fingerprintVersion(FingerprintVersion.LATEST)
                .fingerprintStability(FingerprintStability.STABLE)
                .fingerprintHasher(customHasher)
                .build();
        assertEquals(FingerprintVersion.V2, custom.getFingerprintVersion());
        assertEquals(FingerprintStability.STABLE, custom.getFingerprintStability());
        assertEquals(customHasher, custom.getFingerprintHasher());

        RiskEngineConfig v1Cfg = new RiskEngineConfig.Builder()
                .fingerprintVersion(FingerprintVersion.V1)
                .build();
        assertEquals(FingerprintVersion.V1, v1Cfg.getFingerprintVersion());
    }

    private static DeviceFingerprint buildGoldenFingerprint() {
        DeviceFingerprint fp = new DeviceFingerprint();

        CollectorResult gpu = new CollectorResult("gpu_info");
        gpu.addValue("vendor", "Qualcomm");
        gpu.addValue("renderer", "Adreno (TM) 750");
        gpu.addValue("extensions_hash", "ext_v1");
        gpu.addValue("max_texture_size", "16384");
        fp.addResult(gpu);

        CollectorResult sensor = new CollectorResult("sensor_fingerprint");
        sensor.addValue("tuple_hash", "sens_tuple_1");
        sensor.addValue("vendor_hash", "sens_vendor_1");
        fp.addResult(sensor);

        CollectorResult hw = new CollectorResult("hardware_profile");
        hw.addValue("camera_profile_hash", "cam_1");
        hw.addValue("ram_total_mb_bucket", "12288");
        hw.addValue("battery_technology", "Li-poly");
        fp.addResult(hw);

        CollectorResult cpu = new CollectorResult("cpu_topology");
        cpu.addValue("core_distribution", "0x41|0xd80");
        cpu.addValue("freq_clusters", "300000-3200000");
        cpu.addValue("soc_model", "SM8650");
        cpu.addValue("soc_manufacturer", "QTI");
        fp.addResult(cpu);

        CollectorResult build = new CollectorResult("build_props");
        build.addValue("fingerprint", "google/husky/husky:15/AP3A/1:user/release-keys");
        build.addValue("security_patch", "2026-01-05");
        fp.addResult(build);

        CollectorResult kernel = new CollectorResult("kernel_info");
        kernel.addValue("native", "Linux 6.1.75 aarch64");
        fp.addResult(kernel);

        CollectorResult aid = new CollectorResult("android_id");
        aid.addValue("settings_api", "aid_deadbeef");
        fp.addResult(aid);

        CollectorResult boot = new CollectorResult("boot_id");
        boot.addValue("native_hash", "boot_1234");
        fp.addResult(boot);

        return fp;
    }
}
