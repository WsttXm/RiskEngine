package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.generated.DetectionLists;

import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RootPathListConsistencyTest {
    @Test
    public void javaListsMatchCheckedInIni() throws IOException {
        Path ini = Path.of("src/main/resources/lists/artifact_paths.ini");
        assertTrue("artifact_paths.ini must exist for single-source lists", Files.exists(ini));
        Map<String, List<String>> sections = parse(Files.readAllLines(ini));

        assertEquals(sections.get("su"), List.of(DetectionLists.SU_PATHS));
        assertEquals(sections.get("magisk"), List.of(DetectionLists.MAGISK_PATHS));
        assertEquals(sections.get("kernelsu"), List.of(DetectionLists.KERNELSU_PATHS));
        assertEquals(sections.get("apatch"), List.of(DetectionLists.APATCH_PATHS));
        assertEquals(sections.get("modules"), List.of(DetectionLists.MODULE_PATHS));
        assertEquals(sections.get("emulator_packages"), List.of(DetectionLists.EMULATOR_PACKAGES));
        assertEquals(sections.get("cloud_packages"), List.of(DetectionLists.CLOUD_PACKAGES));
        assertEquals(sections.get("sandbox_packages"), List.of(DetectionLists.SANDBOX_PACKAGES));
        assertEquals(sections.get("tamper_tool_paths"), List.of(DetectionLists.TAMPER_TOOL_PATHS));
        assertEquals(sections.get("properties"), List.of(DetectionLists.ALLOWED_PROPERTIES));
        assertEquals(sections.get("partition_fingerprint_properties"),
                List.of(DetectionLists.PARTITION_FINGERPRINT_PROPERTIES));
        assertEquals(sections.get("cloud_phone_properties"),
                List.of(DetectionLists.CLOUD_PHONE_PROPERTIES));
        assertEquals(sections.get("virtual_gpu_markers"),
                List.of(DetectionLists.VIRTUAL_GPU_MARKERS));
        assertEquals(sections.get("process_tokens"), List.of(DetectionLists.PROCESS_TOKENS));
    }

    @Test
    public void generatedJavaSourceDoesNotContainPlaintextArtifacts() throws IOException {
        String source = readUtf8(Path.of(
                "src/main/java/com/wsttxm/riskenginesdk/generated/DetectionLists.java"));
        assertFalse(source.contains("/system/bin/su"));
        assertFalse(source.contains("/data/adb/magisk"));
        assertFalse(source.contains("frida-server"));
        assertFalse(source.contains("com.lody.virtual"));
    }

    @Test
    public void cppHeaderMatchesCheckedInIni() throws IOException {
        Map<String, List<String>> sections = parse(Files.readAllLines(
                Path.of("src/main/resources/lists/artifact_paths.ini")));
        String header = readUtf8(Path.of("src/main/cpp/generated/detection_lists.h"));

        assertEquals(sections.get("su"), extractCppList(header, "list_su_paths"));
        assertEquals(sections.get("magisk"), extractCppList(header, "list_magisk_paths"));
        assertEquals(sections.get("kernelsu"), extractCppList(header, "list_kernelsu_paths"));
        assertEquals(sections.get("apatch"), extractCppList(header, "list_apatch_paths"));
        assertEquals(sections.get("modules"), extractCppList(header, "list_module_paths"));
        assertEquals(sections.get("tamper_tool_paths"), extractCppList(header, "list_tamper_tool_paths"));
        assertEquals(sections.get("emulator_files"), extractCppList(header, "list_emulator_files"));
        assertEquals(sections.get("properties"), extractCppList(header, "list_allowed_properties"));
        assertEquals(sections.get("process_tokens"), extractCppList(header, "list_process_tokens"));
        assertEquals(sections.get("monitored_libc_symbols"),
                extractCppList(header, "list_monitored_libc_symbols"));
    }

    @Test
    public void manifestQueriesDeclareAllCheckedPackages() throws IOException {
        String manifest = readUtf8(Path.of("src/main/AndroidManifest.xml"));
        Set<String> declared = new LinkedHashSet<>();
        Matcher matcher = Pattern.compile("<package\\s+android:name=\"([^\"]+)\"").matcher(manifest);
        while (matcher.find()) {
            declared.add(matcher.group(1));
        }

        for (String pkg : DetectionLists.EMULATOR_PACKAGES) {
            assertTrue("Missing <queries> for emulator pkg: " + pkg, declared.contains(pkg));
        }
        for (String pkg : DetectionLists.CLOUD_PACKAGES) {
            assertTrue("Missing <queries> for cloud pkg: " + pkg, declared.contains(pkg));
        }
        for (String pkg : DetectionLists.SANDBOX_PACKAGES) {
            assertTrue("Missing <queries> for sandbox pkg: " + pkg, declared.contains(pkg));
        }
    }

    private static String readUtf8(Path path) throws IOException {
        return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    }

    private static List<String> extractCppList(String header, String fnName) {
        int start = header.indexOf(fnName + "()");
        assertTrue("Missing C++ list function: " + fnName, start >= 0);
        int end = header.indexOf("};", start);
        assertTrue("Malformed C++ list function: " + fnName, end > start);
        String body = header.substring(start, end);
        List<String> items = new ArrayList<>();
        Matcher m = Pattern.compile("OBF\\(\"((?:\\\\.|[^\"])*)\"\\)").matcher(body);
        while (m.find()) {
            items.add(m.group(1).replace("\\\"", "\"").replace("\\\\", "\\"));
        }
        return items;
    }

    private static Map<String, List<String>> parse(List<String> lines) {
        Map<String, List<String>> sections = new LinkedHashMap<>();
        String current = null;
        for (String raw : lines) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (line.startsWith("[") && line.endsWith("]")) {
                current = line.substring(1, line.length() - 1);
                sections.putIfAbsent(current, new ArrayList<>());
                continue;
            }
            if (current != null) {
                sections.get(current).add(line);
            }
        }
        return sections;
    }
}
