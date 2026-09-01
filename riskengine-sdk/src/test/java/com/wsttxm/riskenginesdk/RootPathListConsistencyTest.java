package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.generated.DetectionLists;

import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
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
        assertEquals(sections.get("emulator_packages"), List.of(DetectionLists.EMULATOR_PACKAGES));
        assertEquals(sections.get("properties"), List.of(DetectionLists.ALLOWED_PROPERTIES));
        assertEquals(sections.get("process_tokens"), List.of(DetectionLists.PROCESS_TOKENS));
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
