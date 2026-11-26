package com.wsttxm.riskenginesdk.demo.ui;

import com.wsttxm.riskenginesdk.CollectScene;
import com.wsttxm.riskenginesdk.core.DataAggregator;
import com.wsttxm.riskenginesdk.demo.R;
import com.wsttxm.riskenginesdk.model.DetectionExecutionStatus;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.DeviceFingerprint;
import com.wsttxm.riskenginesdk.model.EvidenceItem;
import com.wsttxm.riskenginesdk.model.RiskAction;
import com.wsttxm.riskenginesdk.model.RiskDimension;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;
import com.wsttxm.riskenginesdk.model.ScoreBreakdown;

import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.io.File;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilderFactory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ReportFormatterScoringTest {

    private static ReportFormatter formatter;

    @BeforeClass
    public static void setUpFormatter() throws Exception {
        formatter = new ReportFormatter(loadXmlStrings());
    }

    private static ReportFormatter.StringResolver loadXmlStrings() throws Exception {
        File xml = findStringsXml();
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xml);
        NodeList nodes = doc.getElementsByTagName("string");
        Map<String, String> byName = new HashMap<>();
        for (int i = 0; i < nodes.getLength(); i++) {
            Element el = (Element) nodes.item(i);
            String raw = el.getTextContent()
                    .replace("\\n", "\n")
                    .replace("\\'", "'")
                    .replace("\\\"", "\"");
            byName.put(el.getAttribute("name"), raw);
        }
        Map<Integer, String> byId = new HashMap<>();
        for (Field field : R.string.class.getFields()) {
            String value = byName.get(field.getName());
            if (value != null) {
                byId.put(field.getInt(null), value);
            }
        }
        return new ReportFormatter.StringResolver() {
            @Override
            public String get(int resId) {
                String value = byId.get(resId);
                if (value == null) {
                    throw new IllegalStateException("Missing string resource for id: " + resId);
                }
                return value;
            }

            @Override
            public String get(int resId, Object... formatArgs) {
                return String.format(Locale.ROOT, get(resId), formatArgs);
            }
        };
    }

    private static File findStringsXml() {
        File direct = new File("src/main/res/values/strings.xml");
        if (direct.isFile()) {
            return direct;
        }
        File fromRoot = new File("demo/src/main/res/values/strings.xml");
        if (fromRoot.isFile()) {
            return fromRoot;
        }
        throw new IllegalStateException("Could not locate demo strings.xml from "
                + new File(".").getAbsolutePath());
    }

    @Test
    public void gaugeDefaultMaxScoreIsCalibratedTo100() {
        assertEquals(100, RiskGaugeView.DEFAULT_MAX_SCORE);
    }

    @Test
    public void scoreColorBandsMatchNormalizedRiskLevelRanges() {
        assertEquals(RiskLevel.SAFE, ReportFormatter.riskLevelForScore(0));
        assertEquals(R.color.risk_safe, ReportFormatter.scoreColorRes(0));

        assertEquals(RiskLevel.LOW, ReportFormatter.riskLevelForScore(1));
        assertEquals(RiskLevel.LOW, ReportFormatter.riskLevelForScore(29));
        assertEquals(R.color.risk_low, ReportFormatter.scoreColorRes(29));

        assertEquals(RiskLevel.MEDIUM, ReportFormatter.riskLevelForScore(30));
        assertEquals(RiskLevel.MEDIUM, ReportFormatter.riskLevelForScore(59));
        assertEquals(R.color.risk_medium, ReportFormatter.scoreColorRes(30));
        assertEquals(R.color.risk_medium, ReportFormatter.scoreColorRes(59));

        assertEquals(RiskLevel.HIGH, ReportFormatter.riskLevelForScore(60));
        assertEquals(RiskLevel.HIGH, ReportFormatter.riskLevelForScore(84));
        assertEquals(R.color.risk_high, ReportFormatter.scoreColorRes(60));
        assertEquals(R.color.risk_high, ReportFormatter.scoreColorRes(84));

        assertEquals(RiskLevel.DEADLY, ReportFormatter.riskLevelForScore(85));
        assertEquals(RiskLevel.DEADLY, ReportFormatter.riskLevelForScore(100));
        assertEquals(R.color.risk_deadly, ReportFormatter.scoreColorRes(85));
        assertEquals(R.color.risk_deadly, ReportFormatter.scoreColorRes(100));
    }

    @Test
    public void allFiveRiskActionsHaveDistinctLabelsDescriptionsAndSemanticColors() {
        Set<String> labels = new HashSet<>();
        for (RiskAction action : RiskAction.values()) {
            String label = formatter.riskActionLabel(action);
            String desc = formatter.riskActionDescription(action);
            assertFalse("Blank label for " + action, label.isBlank());
            assertFalse("Blank desc for " + action, desc.isBlank());
            assertTrue("Duplicate label for " + action, labels.add(label));
        }
        assertEquals(R.color.risk_safe, formatter.riskActionColorRes(RiskAction.ALLOW));
        assertEquals(R.color.risk_medium, formatter.riskActionColorRes(RiskAction.CHALLENGE));
        assertEquals(R.color.risk_high, formatter.riskActionColorRes(RiskAction.RESTRICT));
        assertEquals(R.color.risk_deadly, formatter.riskActionColorRes(RiskAction.BLOCK));
        assertEquals(R.color.risk_unknown, formatter.riskActionColorRes(RiskAction.REVIEW));

        assertEquals(R.color.risk_safe_bg, formatter.riskActionBgRes(RiskAction.ALLOW));
        assertEquals(R.color.risk_medium_bg, formatter.riskActionBgRes(RiskAction.CHALLENGE));
        assertEquals(R.color.risk_high_bg, formatter.riskActionBgRes(RiskAction.RESTRICT));
        assertEquals(R.color.risk_deadly_bg, formatter.riskActionBgRes(RiskAction.BLOCK));
        assertEquals(R.color.risk_unknown_bg, formatter.riskActionBgRes(RiskAction.REVIEW));
    }

    @Test
    public void allFourRiskDimensionsAndCollectScenesHaveDistinctLocalizedLabels() {
        Set<String> dimLabels = new HashSet<>();
        for (RiskDimension dim : RiskDimension.values()) {
            String label = formatter.dimensionLabel(dim);
            String desc = formatter.dimensionDescription(dim);
            assertFalse("Blank label for " + dim, label.isBlank());
            assertFalse("Blank desc for " + dim, desc.isBlank());
            assertTrue("Duplicate dimension label for " + dim, dimLabels.add(label));
        }
        assertEquals(4, dimLabels.size());

        Set<String> sceneLabels = new HashSet<>();
        for (CollectScene scene : CollectScene.values()) {
            String label = formatter.collectSceneLabel(scene);
            assertFalse("Blank scene label for " + scene, label.isBlank());
            assertTrue("Duplicate scene label for " + scene, sceneLabels.add(label));
        }
        assertEquals(4, sceneLabels.size());
    }

    @Test
    public void assessmentConfidenceColorReflects70PercentThreshold() {
        assertEquals(R.color.text_primary, ReportFormatter.confidenceColorRes(100));
        assertEquals(R.color.text_primary, ReportFormatter.confidenceColorRes(70));
        assertEquals(R.color.risk_medium, ReportFormatter.confidenceColorRes(69));
        assertEquals(R.color.risk_high, ReportFormatter.confidenceColorRes(35));
    }

    @Test
    public void allSixteenDetectionDomainsHaveDistinctAccurateTitles() {
        String[] all16Domains = {
                "root", "mount_analysis", "hook_framework", "adb",
                "emulator", "debug", "cloud_phone", "custom_rom",
                "app_integrity", "multi_instance", "network_risk", "location_risk",
                "screen_and_fraud", "tee_integrity", "threat_apps", "consistency"
        };
        String fallback = formatter.detectorTitle("nonexistent_domain");
        Set<String> titles = new HashSet<>();
        for (String domain : all16Domains) {
            String title = formatter.detectorTitle(domain);
            assertFalse("Domain fell back to generic title: " + domain, fallback.equals(title));
            assertTrue("Duplicate title for domain: " + domain, titles.add(title));
        }
        assertEquals(16, titles.size());
        assertEquals(fallback, formatter.detectorTitle(null));
    }

    @Test
    public void staleAppZygoteCopyRemovedWhileMagicaPreloadAndCoreSelinuxRemainIntact() {
        DetectionResult stale = new DetectionResult(
                "root",
                RiskLevel.HIGH,
                DetectionStatus.DANGER,
                8, 10, false,
                DetectionExecutionStatus.RISK, 1, 1, 0,
                Collections.emptyList(),
                Collections.singletonList("selinux_dirty_policy"),
                Collections.singletonList(new EvidenceItem(
                        "selinux_dirty_policy",
                        EvidenceItem.SourceLayer.NATIVE,
                        "/sys/fs/selinux/access",
                        "edge",
                        "root_fw",
                        EvidenceItem.Rank.STRONG)),
                "selinux_dirty_policy");
        List<ReportFormatter.EvidenceDetail> staleDetails = formatter.detectionRiskFindings(stale);
        assertEquals(1, staleDetails.size());
        assertFalse("Obsolete AppZygote copy should be removed",
                staleDetails.get(0).title.contains("AppZygote"));
        assertFalse("Obsolete AppZygote risk copy should be removed",
                staleDetails.get(0).risk.contains("app_zygote"));

        DetectionResult magica = new DetectionResult(
                "threat_apps",
                RiskLevel.HIGH,
                DetectionStatus.DANGER,
                8, 10, false,
                DetectionExecutionStatus.RISK, 1, 1, 0,
                Collections.emptyList(),
                Collections.singletonList("threat_app_zygote_preload:me.bmax.apatch"),
                Collections.singletonList(new EvidenceItem(
                        "threat_app_zygote_preload",
                        EvidenceItem.SourceLayer.JAVA,
                        "me.bmax.apatch",
                        ".magica.AppZygotePreload",
                        "root_fw",
                        EvidenceItem.Rank.STRONG)),
                "threat_app_zygote_preload");
        List<ReportFormatter.EvidenceDetail> magicaDetails = formatter.detectionRiskFindings(magica);
        assertEquals(1, magicaDetails.size());
        assertTrue("APatch Magica Zygote preload label must remain intact",
                magicaDetails.get(0).risk.contains(".magica.AppZygotePreload"));
    }

    @Test
    public void scoreBreakdownFormatsAllFourCategoriesWithReadableAttribution() {
        ScoreBreakdown breakdown = new ScoreBreakdown(
                Arrays.asList(
                        new ScoreBreakdown.Entry(
                                ScoreBreakdown.Category.FAMILY,
                                "root_fw",
                                RiskDimension.PRIVILEGE,
                                72,
                                "root"),
                        new ScoreBreakdown.Entry(
                                ScoreBreakdown.Category.CORROBORATION_LIFT,
                                "root_fw",
                                RiskDimension.PRIVILEGE,
                                6,
                                "layers:JAVA+NATIVE"),
                        new ScoreBreakdown.Entry(
                                ScoreBreakdown.Category.CORRELATION_RULE,
                                "C8:spoofed_verified_boot",
                                RiskDimension.PRIVILEGE,
                                80,
                                "signal_correlation"),
                        new ScoreBreakdown.Entry(
                                ScoreBreakdown.Category.HARD_TRIGGER_FLOOR,
                                "frida_pid_port",
                                null,
                                15,
                                "hard_trigger")),
                80,
                95);

        List<ReportFormatter.BreakdownItem> items = formatter.formatScoreBreakdown(breakdown);
        assertEquals(4, items.size());

        // 1. FAMILY
        ReportFormatter.BreakdownItem familyItem = items.get(0);
        assertEquals(ScoreBreakdown.Category.FAMILY, familyItem.category);
        assertTrue(familyItem.title.contains("Root"));
        assertTrue(familyItem.sourceSummary.contains("ROOT检测"));
        assertEquals("+72", familyItem.pointsLabel);
        assertEquals(formatter.dimensionLabel(RiskDimension.PRIVILEGE), familyItem.dimensionLabel);

        // 2. CORROBORATION_LIFT
        ReportFormatter.BreakdownItem liftItem = items.get(1);
        assertEquals(ScoreBreakdown.Category.CORROBORATION_LIFT, liftItem.category);
        assertTrue(liftItem.sourceSummary.contains("Java + Native"));
        assertEquals("+6", liftItem.pointsLabel);

        // 3. CORRELATION_RULE
        ReportFormatter.BreakdownItem corrItem = items.get(2);
        assertEquals(ScoreBreakdown.Category.CORRELATION_RULE, corrItem.category);
        assertTrue(corrItem.title.contains("C8"));
        assertEquals("+80", corrItem.pointsLabel);

        // 4. HARD_TRIGGER_FLOOR
        ReportFormatter.BreakdownItem hardItem = items.get(3);
        assertEquals(ScoreBreakdown.Category.HARD_TRIGGER_FLOOR, hardItem.category);
        assertTrue(hardItem.detail.contains("frida_pid_port"));
        assertEquals("+15", hardItem.pointsLabel);
        assertEquals(R.color.risk_deadly, hardItem.accentColorRes);
    }

    @Test
    public void formatCorroborationSourceRendersLiveAggregatedMultiLayerAndMultiDomainReports() {
        DataAggregator aggregator = new DataAggregator();

        // 1) Real DataAggregator report with JAVA + NATIVE corroboration (emits "layers:JAVA,NATIVE")
        DetectionResult multiLayerRoot = new DetectionResult(
                "root", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false,
                DetectionExecutionStatus.RISK, 2, 2, 0,
                Collections.emptyList(),
                Collections.singletonList("su_found:/system/bin/su"),
                Arrays.asList(
                        new EvidenceItem("su_found", EvidenceItem.SourceLayer.JAVA,
                                "/system/bin/su", "exists", "root_fw", EvidenceItem.Rank.MEDIUM),
                        new EvidenceItem("su_found", EvidenceItem.SourceLayer.NATIVE,
                                "/system/bin/su", "exists", "root_fw", EvidenceItem.Rank.STRONG)),
                "su_found:/system/bin/su");
        RiskReport report = aggregator.aggregate(
                Collections.emptyList(), Collections.singletonList(multiLayerRoot), CollectScene.STANDARD);

        List<ReportFormatter.BreakdownItem> items = formatter.formatScoreBreakdown(report.getScoreBreakdown());
        ReportFormatter.BreakdownItem liftItem = null;
        for (ReportFormatter.BreakdownItem item : items) {
            if (item.category == ScoreBreakdown.Category.CORROBORATION_LIFT) {
                liftItem = item;
                break;
            }
        }
        assertTrue("Expected CORROBORATION_LIFT entry from live DataAggregator report", liftItem != null);
        assertTrue("Expected formatted 'Java + Native', got: " + liftItem.sourceSummary,
                liftItem.sourceSummary.contains("Java + Native"));
        assertFalse("Must not leak raw comma-separated layer tokens: " + liftItem.sourceSummary,
                liftItem.sourceSummary.contains("JAVA,NATIVE"));

        // 2) Real DataAggregator report with NATIVE + ISOLATED corroboration across root + mount_analysis
        DetectionResult nativeRoot = new DetectionResult(
                "root", RiskLevel.HIGH, DetectionStatus.DANGER,
                8, 10, false,
                Collections.singletonList("su_found:/system/bin/su"), "su_found:/system/bin/su")
                .withEvidenceItems(Collections.singletonList(new EvidenceItem(
                        "su_found", EvidenceItem.SourceLayer.NATIVE,
                        "/system/bin/su", "exists", "root_fw", EvidenceItem.Rank.STRONG)));
        DetectionResult isolatedMount = new DetectionResult(
                "mount_analysis", RiskLevel.MEDIUM, DetectionStatus.WARNING,
                4, 10, false,
                Collections.singletonList("isolated_mount_diff:/data/adb"), "isolated_mount_diff:/data/adb")
                .withEvidenceItems(Collections.singletonList(new EvidenceItem(
                        "isolated_mount_diff", EvidenceItem.SourceLayer.ISOLATED,
                        "/data/adb", "diff", "root_fw", EvidenceItem.Rank.MEDIUM)));
        RiskReport isoReport = aggregator.aggregate(
                Collections.emptyList(), Arrays.asList(nativeRoot, isolatedMount), CollectScene.STANDARD);
        ReportFormatter.BreakdownItem isoLift = null;
        for (ReportFormatter.BreakdownItem item : formatter.formatScoreBreakdown(isoReport.getScoreBreakdown())) {
            if (item.category == ScoreBreakdown.Category.CORROBORATION_LIFT) {
                isoLift = item;
                break;
            }
        }
        assertTrue("Expected NATIVE+ISOLATED corroboration lift", isoLift != null);
        assertTrue("Expected Native 层 in: " + isoLift.sourceSummary,
                isoLift.sourceSummary.contains("Native 层"));
        assertTrue("Expected 隔离进程 in: " + isoLift.sourceSummary,
                isoLift.sourceSummary.contains("隔离进程"));
        assertFalse("Must not leak raw tokens: " + isoLift.sourceSummary,
                isoLift.sourceSummary.contains("NATIVE,ISOLATED"));
    }

    @Test
    public void scoreBreakdownFiltersPerDetectorAndGeneratesCopyableReport() {
        EvidenceItem fridaItem = new EvidenceItem(
                "frida_dbus_port",
                EvidenceItem.SourceLayer.NATIVE,
                EnumSet.of(EvidenceItem.SourceLayer.JAVA, EvidenceItem.SourceLayer.NATIVE),
                "127.0.0.1:27042",
                "frida_pid_port",
                "frida",
                EvidenceItem.Rank.STRONG);
        DetectionResult hookDet = new DetectionResult(
                "hook_framework",
                RiskLevel.DEADLY,
                DetectionStatus.DANGER,
                10, 10, false,
                DetectionExecutionStatus.RISK, 1, 1, 0,
                Collections.emptyList(),
                Collections.singletonList("frida_pid_port"),
                Collections.singletonList(fridaItem),
                "frida_pid_port");
        RiskReport report = new RiskReport(
                new DeviceFingerprint(),
                Collections.singletonList(hookDet),
                CollectScene.PAYMENT);

        assertFalse(formatter.breakdownItemsForDetector(report, "hook_framework").isEmpty());
        assertTrue(formatter.breakdownItemsForDetector(report, "adb").isEmpty());

        String summaryLine = formatter.breakdownSummaryLine(report);
        assertTrue(summaryLine.contains("Hard Trigger"));
        assertTrue(summaryLine.contains("95"));

        String copyText = formatter.formatScoreBreakdownForCopy(report);
        assertTrue(copyText.contains("95 / 100"));
        assertTrue(copyText.contains("frida_pid_port"));
        assertTrue(copyText.contains(formatter.riskActionLabel(RiskAction.BLOCK)));
    }

    @Test
    public void redactedSummaryIncludesNormalizedScoreActionConfidenceDimensionsAndBreakdown() {
        EvidenceItem rootItem = new EvidenceItem(
                "su_found",
                EvidenceItem.SourceLayer.NATIVE,
                EnumSet.of(EvidenceItem.SourceLayer.JAVA, EvidenceItem.SourceLayer.NATIVE),
                "/system/xbin/su",
                "su_binary",
                "root_fw",
                EvidenceItem.Rank.STRONG);
        DetectionResult rootDet = new DetectionResult(
                "root",
                RiskLevel.HIGH,
                DetectionStatus.DANGER,
                8, 10, false,
                DetectionExecutionStatus.RISK, 3, 3, 0,
                Collections.emptyList(),
                Collections.singletonList("su_found:/system/xbin/su"),
                Collections.singletonList(rootItem),
                "su_found:/system/xbin/su");
        RiskReport report = new RiskReport(
                new DeviceFingerprint(),
                Collections.singletonList(rootDet),
                CollectScene.LOGIN);

        String redacted = formatter.buildRedactedSummary(report);
        assertTrue(redacted.contains("/ 100"));
        assertTrue(redacted.contains("推荐动作：" + formatter.riskActionLabel(report.getRecommendedAction())));
        assertTrue(redacted.contains("评估置信度：" + report.getConfidencePercent() + "%"));
        for (RiskDimension dim : RiskDimension.values()) {
            assertTrue("Missing dimension in redacted report: " + dim,
                    redacted.contains(formatter.dimensionLabel(dim)));
        }
        assertTrue("Missing Score Breakdown in redacted report",
                redacted.contains("评分归因："));
        assertFalse("Redacted summary must not leak raw file paths",
                redacted.contains("/system/xbin/su"));
    }
}
