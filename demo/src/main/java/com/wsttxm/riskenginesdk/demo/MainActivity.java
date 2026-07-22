package com.wsttxm.riskenginesdk.demo;

import android.animation.ValueAnimator;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.HapticFeedbackConstants;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.progressindicator.CircularProgressIndicator;
import com.google.android.material.progressindicator.LinearProgressIndicator;
import com.wsttxm.riskenginesdk.RiskEngine;
import com.wsttxm.riskenginesdk.RiskEngineCallback;
import com.wsttxm.riskenginesdk.RiskEngineConfig;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import java.lang.ref.WeakReference;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class MainActivity extends AppCompatActivity {

    private static final Object STATE_LOCK = new Object();
    private static WeakReference<MainActivity> activeActivity = new WeakReference<>(null);
    private static RiskReport latestReport;
    private static Throwable latestError;
    private static boolean collectionInFlight;
    private static long collectionStartedAtMs;
    private static long latestElapsedMs;
    private static long activeRequestToken;

    private MaterialButton btnCollect;
    private MaterialButton btnCopyReport;
    private MaterialCardView cardStatus;
    private MaterialCardView cardDetections;
    private MaterialCardView cardInconsistent;
    private MaterialCardView cardFingerprint;
    private CircularProgressIndicator progressCollecting;
    private LinearProgressIndicator progressRisk;

    private TextView tvRiskLevel;
    private TextView tvStatusInfo;
    private TextView tvLocalStatus;
    private TextView tvScoreCaption;
    private TextView tvCoverageSummary;
    private LinearLayout layoutStats;
    private TextView tvStatRiskScore;
    private TextView tvStatFingerprints;
    private TextView tvStatElapsed;
    private TextView tvDetectionsHeader;
    private LinearLayout layoutDetections;
    private TextView tvInconsistentHeader;
    private LinearLayout layoutInconsistent;
    private TextView tvFingerprintHeader;
    private LinearLayout layoutFingerprint;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initViews();
        initSdk();
        btnCollect.setOnClickListener(v -> startCollection());
    }

    @Override
    protected void onStart() {
        super.onStart();
        synchronized (STATE_LOCK) {
            activeActivity = new WeakReference<>(this);
        }
        renderSharedState();
    }

    @Override
    protected void onStop() {
        synchronized (STATE_LOCK) {
            if (activeActivity.get() == this) {
                activeActivity.clear();
            }
        }
        super.onStop();
    }

    @Override
    protected void onDestroy() {
        if (isFinishing()) {
            synchronized (STATE_LOCK) {
                activeRequestToken++;
                collectionInFlight = false;
                latestReport = null;
                latestError = null;
            }
            RiskEngine.shutdown();
        }
        super.onDestroy();
    }

    private void initViews() {
        btnCollect = findViewById(R.id.btnCollect);
        btnCopyReport = findViewById(R.id.btnCopyReport);
        cardStatus = findViewById(R.id.cardStatus);
        cardDetections = findViewById(R.id.cardDetections);
        cardInconsistent = findViewById(R.id.cardInconsistent);
        cardFingerprint = findViewById(R.id.cardFingerprint);
        progressCollecting = findViewById(R.id.progressCollecting);
        progressRisk = findViewById(R.id.progressRisk);
        tvRiskLevel = findViewById(R.id.tvRiskLevel);
        tvStatusInfo = findViewById(R.id.tvStatusInfo);
        tvLocalStatus = findViewById(R.id.tvLocalStatus);
        tvScoreCaption = findViewById(R.id.tvScoreCaption);
        tvCoverageSummary = findViewById(R.id.tvCoverageSummary);
        layoutStats = findViewById(R.id.layoutStats);
        tvStatRiskScore = findViewById(R.id.tvStatRiskScore);
        tvStatFingerprints = findViewById(R.id.tvStatFingerprints);
        tvStatElapsed = findViewById(R.id.tvStatElapsed);
        tvDetectionsHeader = findViewById(R.id.tvDetectionsHeader);
        layoutDetections = findViewById(R.id.layoutDetections);
        tvInconsistentHeader = findViewById(R.id.tvInconsistentHeader);
        layoutInconsistent = findViewById(R.id.layoutInconsistent);
        tvFingerprintHeader = findViewById(R.id.tvFingerprintHeader);
        layoutFingerprint = findViewById(R.id.layoutFingerprint);
        btnCopyReport.setOnClickListener(v -> copyRedactedReport());
    }

    private void initSdk() {
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .debugLog(BuildConfig.DEBUG)
                .collectTimeout(15_000)
                .build();
        RiskEngine.initIfNeeded(this, config);
    }

    private void startCollection() {
        final long requestToken;
        synchronized (STATE_LOCK) {
            if (collectionInFlight) {
                Toast.makeText(this, R.string.collecting_toast, Toast.LENGTH_SHORT).show();
                btnCollect.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK);
                return;
            }
            collectionInFlight = true;
            collectionStartedAtMs = System.currentTimeMillis();
            latestReport = null;
            latestError = null;
            requestToken = ++activeRequestToken;
        }

        showLoadingState();
        RiskEngine.collect(createCollectionCallback(requestToken));
    }

    private static RiskEngineCallback createCollectionCallback(long requestToken) {
        return new RiskEngineCallback() {
            @Override
            public void onSuccess(RiskReport report) {
                synchronized (STATE_LOCK) {
                    if (requestToken != activeRequestToken) {
                        return;
                    }
                    latestElapsedMs = Math.max(0,
                            System.currentTimeMillis() - collectionStartedAtMs);
                    latestReport = report;
                    latestError = null;
                    collectionInFlight = false;
                }
                deliverSharedState(true);
            }

            @Override
            public void onError(Throwable error) {
                synchronized (STATE_LOCK) {
                    if (requestToken != activeRequestToken) {
                        return;
                    }
                    latestReport = null;
                    latestError = error;
                    collectionInFlight = false;
                }
                deliverSharedState(false);
            }
        };
    }

    private static void deliverSharedState(boolean success) {
        MainActivity activity;
        synchronized (STATE_LOCK) {
            activity = activeActivity.get();
        }
        if (activity != null) {
            activity.runOnUiThread(() -> {
                activity.renderSharedState();
                activity.btnCollect.performHapticFeedback(success
                        ? HapticFeedbackConstants.CONFIRM
                        : HapticFeedbackConstants.REJECT);
            });
        }
    }

    private void renderSharedState() {
        RiskReport report;
        Throwable error;
        boolean inFlight;
        long elapsedMs;
        synchronized (STATE_LOCK) {
            report = latestReport;
            error = latestError;
            inFlight = collectionInFlight;
            elapsedMs = latestElapsedMs;
        }

        if (inFlight) {
            showLoadingState();
        } else if (report != null) {
            displayReport(report, elapsedMs);
        } else if (error != null) {
            showErrorState(error);
        } else {
            showIdleState();
        }
    }

    private void showIdleState() {
        progressCollecting.setVisibility(View.GONE);
        tvLocalStatus.setText(R.string.status_ready_code);
        styleLocalStatus(getString(R.string.status_ready_code),
                getColor(R.color.primary), R.color.chip_bg);
        tvRiskLevel.setText(R.string.status_ready);
        tvRiskLevel.setTextColor(getColor(R.color.text_primary));
        tvStatusInfo.setText(R.string.status_ready_description);
        tvScoreCaption.setText(R.string.score_idle_description);
        progressRisk.setIndicatorColor(getColor(R.color.primary));
        progressRisk.setProgressCompat(0, false);
        progressRisk.setContentDescription(getString(R.string.risk_progress_idle));
        layoutStats.setVisibility(View.GONE);
        tvCoverageSummary.setVisibility(View.GONE);
        btnCollect.setText(R.string.collect_action);
        btnCollect.setContentDescription(getString(R.string.collect_action));
        hideResultCards();
        btnCopyReport.setVisibility(View.GONE);
    }

    private void showLoadingState() {
        progressCollecting.setVisibility(View.VISIBLE);
        tvLocalStatus.setText(R.string.status_analyzing_code);
        styleLocalStatus(getString(R.string.status_analyzing_code),
                getColor(R.color.primary), R.color.chip_bg);
        tvRiskLevel.setText(R.string.status_analyzing);
        tvRiskLevel.setTextColor(getColor(R.color.text_primary));
        tvStatusInfo.setText(R.string.status_analyzing_description);
        tvScoreCaption.setText(R.string.score_calculating_description);
        progressRisk.setIndicatorColor(getColor(R.color.primary));
        progressRisk.setProgressCompat(0, false);
        progressRisk.setContentDescription(getString(R.string.score_calculating_description));
        layoutStats.setVisibility(View.GONE);
        tvCoverageSummary.setVisibility(View.GONE);
        btnCollect.setText(R.string.collecting_action);
        btnCollect.setContentDescription(getString(R.string.collecting_action));
        hideResultCards();
        btnCopyReport.setVisibility(View.GONE);
    }

    private void showErrorState(Throwable error) {
        progressCollecting.setVisibility(View.GONE);
        styleLocalStatus(getString(R.string.status_error_code),
                getColor(R.color.risk_unknown), R.color.unknown_bg);
        tvRiskLevel.setText(R.string.collection_failed);
        tvRiskLevel.setTextColor(getColor(R.color.risk_unknown));
        String message = error.getMessage();
        if (message == null || message.isBlank()) {
            message = getString(R.string.unknown_error);
        }
        tvStatusInfo.setText(getString(R.string.collection_failed_description, message));
        tvScoreCaption.setText(R.string.score_error_description);
        progressRisk.setIndicatorColor(getColor(R.color.risk_unknown));
        progressRisk.setProgressCompat(0, animationsEnabled());
        progressRisk.setContentDescription(getString(R.string.risk_progress_error));
        layoutStats.setVisibility(View.GONE);
        tvCoverageSummary.setVisibility(View.GONE);
        btnCollect.setText(R.string.retry_action);
        btnCollect.setContentDescription(getString(R.string.retry_action));
        hideResultCards();
        btnCopyReport.setVisibility(View.GONE);
    }

    private void displayReport(RiskReport report, long elapsedMs) {
        progressCollecting.setVisibility(View.GONE);
        RiskLevel level = report.getOverallRiskLevel();
        int riskColor = getRiskColor(level);
        styleLocalStatus(getRiskLabel(level), riskColor, riskBackground(level));
        tvRiskLevel.setText(getRiskLabel(level));
        tvRiskLevel.setTextColor(riskColor);
        tvStatusInfo.setText(buildRiskDescription(report));

        int riskPercent = Math.min(100,
                Math.round((report.getRiskScore()
                        / (float) report.getDisplayThresholdMaximum()) * 100f));
        progressRisk.setIndicatorColor(riskColor);
        progressRisk.setProgressCompat(riskPercent, animationsEnabled());
        progressRisk.setContentDescription(getString(R.string.risk_progress_value,
                report.getRiskScore(), report.getDisplayThresholdMaximum()));

        String time = DateFormat.getDateTimeInstance(
                DateFormat.SHORT, DateFormat.MEDIUM, Locale.getDefault())
                .format(new Date(report.getTimestampMs()));
        tvScoreCaption.setText(getString(R.string.score_report_description,
                report.getSdkVersion(), time, report.getRiskScore(),
                report.getDisplayThresholdMaximum()));

        layoutStats.setVisibility(View.VISIBLE);
        tvStatRiskScore.setText(String.valueOf(report.getRiskScore()));
        tvStatFingerprints.setText(getString(
                R.string.coverage_percent, report.getCoveragePercent()));
        tvStatElapsed.setText(formatElapsed(elapsedMs));
        tvCoverageSummary.setVisibility(View.VISIBLE);
        tvCoverageSummary.setText(getString(R.string.coverage_summary,
                report.getCompletedCheckCount(), report.getCheckCount(),
                report.getDangerCount(), report.getWarningCount(), report.getIncompleteCheckCount(),
                report.getFingerprint().getResults().size()));

        btnCollect.setText(R.string.collect_again_action);
        btnCollect.setContentDescription(getString(R.string.collect_again_action));
        displayDetections(report);
        displayInconsistentFields(report);
        displayFingerprint(report);
        btnCopyReport.setVisibility(View.VISIBLE);
    }

    private void displayDetections(RiskReport report) {
        layoutDetections.removeAllViews();
        List<DetectionResult> detections = new ArrayList<>(report.getDetections());
        detections.sort((left, right) -> Integer.compare(
                detectionPriority(left), detectionPriority(right)));

        if (detections.isEmpty()) {
            cardDetections.setVisibility(View.GONE);
            return;
        }

        int attentionCount = 0;
        for (DetectionResult detection : detections) {
            if (detection.getStatus() == DetectionStatus.DANGER
                    || detection.getStatus() == DetectionStatus.WARNING) {
                attentionCount++;
            }
        }
        tvDetectionsHeader.setText(getString(R.string.detections_header_summary,
                detections.size(), attentionCount, countIncompleteDetections(detections)));

        for (int index = 0; index < detections.size(); index++) {
            layoutDetections.addView(createDetectionRow(detections.get(index)));
            if (index < detections.size() - 1) {
                layoutDetections.addView(createDivider());
            }
        }
        revealCard(cardDetections, 0);
    }

    private View createDetectionRow(DetectionResult detection) {
        LinearLayout row = createInteractiveRow();

        TextView disclosure = addRowHeader(row, detectionStatusColor(detection),
                detectorTitle(detection.getDetectorName()), detection.getDetectorName(),
                detectionStatusLabel(detection), detectionStatusColor(detection),
                detectionStatusBackground(detection));

        TextView summary = createText(detectionSummary(detection),
                12, R.color.text_secondary, Typeface.NORMAL);
        LinearLayout.LayoutParams summaryParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        summaryParams.leftMargin = dp(20);
        summaryParams.topMargin = dp(7);
        summary.setLayoutParams(summaryParams);
        summary.setLineSpacing(0, 1.08f);
        row.addView(summary);

        LinearLayout details = createDetailsContainer();
        TextView detailLabel = createText(getString(R.string.technical_evidence),
                11, R.color.text_tertiary, Typeface.BOLD);
        details.addView(detailLabel);
        TextView evidence = createText(detectionTechnicalDetails(detection),
                11, R.color.text_secondary, Typeface.NORMAL);
        evidence.setTypeface(Typeface.MONOSPACE);
        evidence.setTextIsSelectable(true);
        evidence.setLineSpacing(dp(2), 1f);
        LinearLayout.LayoutParams evidenceParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        evidenceParams.topMargin = dp(5);
        evidence.setLayoutParams(evidenceParams);
        details.addView(evidence);
        row.addView(details);

        row.setContentDescription(getString(R.string.row_content_description,
                detectorTitle(detection.getDetectorName()), detectionStatusLabel(detection)));
        row.setOnClickListener(v -> toggleDetails(details, disclosure));
        return row;
    }

    private void displayInconsistentFields(RiskReport report) {
        layoutInconsistent.removeAllViews();
        List<String> inconsistent = report.getFingerprint().getInconsistentFields();
        if (inconsistent.isEmpty()) {
            cardInconsistent.setVisibility(View.GONE);
            return;
        }

        tvInconsistentHeader.setText(getString(
                R.string.inconsistent_header_summary, inconsistent.size()));
        for (String field : inconsistent) {
            TextView fieldView = createText(
                    collectorTitle(field) + "  ·  " + field,
                    13, R.color.inconsistent_text, Typeface.BOLD);
            fieldView.setPadding(0, dp(7), 0, dp(3));
            layoutInconsistent.addView(fieldView);

            CollectorResult result = report.getFingerprint().getResults().get(field);
            if (result != null) {
                TextView sources = createText(collectorTechnicalDetails(result),
                        11, R.color.inconsistent_text, Typeface.NORMAL);
                sources.setTypeface(Typeface.MONOSPACE);
                sources.setTextIsSelectable(true);
                layoutInconsistent.addView(sources);
            }
        }
        revealCard(cardInconsistent, 1);
    }

    private void displayFingerprint(RiskReport report) {
        layoutFingerprint.removeAllViews();
        Map<String, CollectorResult> results = report.getFingerprint().getResults();
        if (results.isEmpty()) {
            cardFingerprint.setVisibility(View.GONE);
            return;
        }

        List<CollectorResult> collected = new ArrayList<>();
        List<CollectorResult> synthetic = new ArrayList<>();
        int unavailable = 0;
        for (CollectorResult result : results.values()) {
            if (isSyntheticCollector(result.getFieldName())) {
                synthetic.add(result);
                continue;
            }
            collected.add(result);
            if (result.getStatus() != CollectorResult.Status.SUCCESS) {
                unavailable++;
            }
        }
        tvFingerprintHeader.setText(getString(
                R.string.fingerprint_header_summary, collected.size(), unavailable));

        int index = 0;
        for (CollectorResult result : collected) {
            layoutFingerprint.addView(createFingerprintRow(result));
            if (index < collected.size() - 1) {
                layoutFingerprint.addView(createDivider());
            }
            index++;
        }
        if (!synthetic.isEmpty()) {
            TextView section = createText(getString(R.string.synthetic_analysis_title),
                    13, R.color.text_secondary, Typeface.BOLD);
            section.setPadding(dp(2), dp(20), dp(2), dp(7));
            layoutFingerprint.addView(section);
            for (int syntheticIndex = 0; syntheticIndex < synthetic.size(); syntheticIndex++) {
                layoutFingerprint.addView(createFingerprintRow(synthetic.get(syntheticIndex)));
                if (syntheticIndex < synthetic.size() - 1) {
                    layoutFingerprint.addView(createDivider());
                }
            }
        }
        revealCard(cardFingerprint, 2);
    }

    private boolean isSyntheticCollector(String name) {
        return "hook_memory_signals".equals(name)
                || "runtime_integrity_score_inputs".equals(name);
    }

    private void copyRedactedReport() {
        RiskReport report;
        synchronized (STATE_LOCK) {
            report = latestReport;
        }
        if (report == null) return;
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null) return;
        clipboard.setPrimaryClip(ClipData.newPlainText(
                getString(R.string.copy_redacted_report_label), buildRedactedSummary(report)));
        Toast.makeText(this, R.string.copy_redacted_report_success, Toast.LENGTH_SHORT).show();
    }

    private String buildRedactedSummary(RiskReport report) {
        StringBuilder summary = new StringBuilder();
        summary.append(getString(R.string.redacted_report_header,
                report.getSdkVersion(), getRiskLabel(report.getOverallRiskLevel()),
                report.getRiskScore(), report.getDisplayThresholdMaximum(),
                report.getCompletedCheckCount(), report.getCheckCount(),
                report.getDangerCount(), report.getWarningCount(),
                report.getIncompleteCheckCount()));
        for (DetectionResult detection : report.getDetections()) {
            if (detection.getDetectorName().startsWith("collector:")) continue;
            summary.append(getString(R.string.redacted_report_item,
                    detectorTitle(detection.getDetectorName()), detectionStatusLabel(detection)));
            if (!detection.getDetails().isEmpty()) {
                summary.append(getString(R.string.redacted_report_reason,
                        humanizeEvidence(detection.getDetails().get(0))));
            }
        }
        summary.append(getString(R.string.redacted_report_footer));
        return summary.toString();
    }

    private View createFingerprintRow(CollectorResult result) {
        LinearLayout row = createInteractiveRow();
        int statusColor = collectorStatusColor(result.getStatus());
        TextView disclosure = addRowHeader(row, null,
                collectorTitle(result.getFieldName()), getString(R.string.field_meta,
                        result.getFieldName(), collectorSensitivityLabel(result.getFieldName())),
                collectorStatusLabel(result.getStatus()), statusColor,
                collectorStatusBackground(result.getStatus()));

        TextView summary = createText(collectorSummary(result),
                12, R.color.text_secondary, Typeface.NORMAL);
        LinearLayout.LayoutParams summaryParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        summaryParams.topMargin = dp(7);
        summary.setLayoutParams(summaryParams);
        summary.setMaxLines(3);
        summary.setEllipsize(TextUtils.TruncateAt.END);
        row.addView(summary);

        LinearLayout details = createDetailsContainer();
        TextView detailLabel = createText(getString(R.string.source_values),
                11, R.color.text_tertiary, Typeface.BOLD);
        details.addView(detailLabel);
        TextView technicalValues = createText(collectorTechnicalDetails(result),
                11, R.color.text_secondary, Typeface.NORMAL);
        technicalValues.setTypeface(Typeface.MONOSPACE);
        technicalValues.setTextIsSelectable(true);
        technicalValues.setLineSpacing(dp(2), 1f);
        LinearLayout.LayoutParams technicalParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        technicalParams.topMargin = dp(5);
        technicalValues.setLayoutParams(technicalParams);
        details.addView(technicalValues);
        row.addView(details);

        row.setContentDescription(getString(R.string.row_content_description,
                collectorTitle(result.getFieldName()), collectorStatusLabel(result.getStatus())));
        row.setOnClickListener(v -> toggleDetails(details, disclosure));
        return row;
    }

    private LinearLayout createInteractiveRow() {
        LinearLayout row = new LinearLayout(this);
        row.setClickable(true);
        row.setFocusable(true);
        row.setMinimumHeight(dp(64));
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(dp(2), dp(13), dp(2), dp(13));
        TypedValue selectable = new TypedValue();
        if (getTheme().resolveAttribute(
                android.R.attr.selectableItemBackground, selectable, true)) {
            row.setBackgroundResource(selectable.resourceId);
        }
        return row;
    }

    private TextView addRowHeader(LinearLayout row, Integer dotColor, String titleText,
                                  String technicalText, String badgeText, int badgeTextColor,
                                  int badgeBackgroundColor) {
        LinearLayout header = new LinearLayout(this);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setOrientation(LinearLayout.HORIZONTAL);

        if (dotColor != null) {
            View dot = new View(this);
            LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(dp(9), dp(9));
            dotParams.rightMargin = dp(11);
            dot.setLayoutParams(dotParams);
            dot.setBackground(createCircleDrawable(dotColor));
            header.addView(dot);
        }

        LinearLayout titleGroup = new LinearLayout(this);
        titleGroup.setOrientation(LinearLayout.VERTICAL);
        titleGroup.setLayoutParams(new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        titleGroup.addView(createText(titleText, 14, R.color.text_primary, Typeface.BOLD));
        TextView technicalName = createText(
                technicalText, 11, R.color.text_tertiary, Typeface.NORMAL);
        technicalName.setTypeface(Typeface.MONOSPACE);
        titleGroup.addView(technicalName);
        header.addView(titleGroup);

        header.addView(createStatusBadge(badgeText, badgeTextColor, badgeBackgroundColor));
        TextView disclosure = createText(getString(R.string.expand_details),
                11, R.color.text_tertiary, Typeface.NORMAL);
        disclosure.setPadding(dp(8), 0, 0, 0);
        header.addView(disclosure);
        row.addView(header);
        return disclosure;
    }

    private LinearLayout createDetailsContainer() {
        LinearLayout details = new LinearLayout(this);
        details.setOrientation(LinearLayout.VERTICAL);
        details.setPadding(dp(20), dp(12), 0, dp(3));
        details.setVisibility(View.GONE);
        details.setTag(Boolean.FALSE);
        return details;
    }

    private void toggleDetails(View details, TextView disclosure) {
        boolean expanding = !Boolean.TRUE.equals(details.getTag());
        details.setTag(expanding);
        disclosure.setText(expanding
                ? R.string.collapse_details
                : R.string.expand_details);
        details.animate().cancel();

        if (!animationsEnabled()) {
            details.setAlpha(1f);
            details.setTranslationY(0f);
            details.setVisibility(expanding ? View.VISIBLE : View.GONE);
            return;
        }

        if (expanding) {
            details.setVisibility(View.VISIBLE);
            if (details.getAlpha() >= 1f) {
                details.setAlpha(0f);
                details.setTranslationY(-dp(4));
            }
            details.animate()
                    .alpha(1f)
                    .translationY(0f)
                    .setDuration(220)
                    .setInterpolator(new DecelerateInterpolator())
                    .start();
        } else {
            details.animate()
                    .alpha(0f)
                    .translationY(-dp(4))
                    .setDuration(150)
                    .setInterpolator(new DecelerateInterpolator())
                    .withEndAction(() -> {
                        if (!Boolean.TRUE.equals(details.getTag())) {
                            details.setVisibility(View.GONE);
                            details.setAlpha(1f);
                            details.setTranslationY(0f);
                        }
                    })
                    .start();
        }
    }

    private void revealCard(View card, int order) {
        card.animate().cancel();
        card.setVisibility(View.VISIBLE);
        if (!animationsEnabled()) {
            card.setAlpha(1f);
            card.setTranslationY(0f);
            card.setScaleX(1f);
            card.setScaleY(1f);
            return;
        }
        card.setAlpha(0f);
        card.setTranslationY(dp(12));
        card.setScaleX(0.985f);
        card.setScaleY(0.985f);
        card.animate()
                .alpha(1f)
                .translationY(0f)
                .scaleX(1f)
                .scaleY(1f)
                .setStartDelay(Math.min(135, order * 45L))
                .setDuration(320)
                .setInterpolator(new DecelerateInterpolator())
                .start();
    }

    private void hideResultCards() {
        hideImmediately(cardDetections);
        hideImmediately(cardInconsistent);
        hideImmediately(cardFingerprint);
    }

    private void hideImmediately(View view) {
        view.animate().cancel();
        view.setVisibility(View.GONE);
        view.setAlpha(1f);
        view.setTranslationY(0f);
        view.setScaleX(1f);
        view.setScaleY(1f);
    }

    private boolean animationsEnabled() {
        return ValueAnimator.areAnimatorsEnabled();
    }

    private int detectionPriority(DetectionResult detection) {
        switch (detection.getStatus()) {
            case DANGER:
                return detection.isInformational() ? 1 : 0;
            case WARNING:
                return detection.isInformational() ? 3 : 2;
            case UNKNOWN:
                return 4;
            case NORMAL:
            default:
                return 5;
        }
    }

    private int countIncompleteDetections(List<DetectionResult> detections) {
        int count = 0;
        for (DetectionResult detection : detections) {
            switch (detection.getExecutionStatus()) {
                case PARTIAL:
                case UNAVAILABLE:
                case TIMEOUT:
                case ERROR:
                    count++;
                    break;
                default:
                    break;
            }
        }
        return count;
    }

    private String detectionSummary(DetectionResult detection) {
        if (detection.getStatus() == DetectionStatus.UNKNOWN) {
            return getString(R.string.detection_unavailable_summary,
                    executionStatusLabel(detection));
        }
        if (detection.getStatus() == DetectionStatus.NORMAL) {
            return detection.getExecutionStatus()
                    == com.wsttxm.riskenginesdk.model.DetectionExecutionStatus.PARTIAL
                    ? getString(R.string.detection_partial_safe_summary,
                            detection.getChecksSucceeded(), detection.getChecksAttempted())
                    : getString(R.string.detection_normal_summary);
        }
        String reason = detection.getDetails().isEmpty()
                ? getString(R.string.no_specific_evidence)
                : humanizeEvidence(detection.getDetails().get(0));
        if (detection.isInformational()) {
            return getString(R.string.detection_informational_summary, reason);
        }
        if (detection.getStatus() == DetectionStatus.DANGER) {
            return getString(R.string.detection_danger_summary, reason);
        }
        return getString(R.string.detection_warning_summary, reason);
    }

    private String detectionTechnicalDetails(DetectionResult detection) {
        StringBuilder text = new StringBuilder();
        text.append(getString(R.string.technical_execution_status,
                executionStatusLabel(detection)));
        text.append('\n').append(getString(R.string.technical_score,
                detection.getScore(), detection.getMaxScore(),
                detection.isInformational() ? getString(R.string.yes) : getString(R.string.no)));
        text.append('\n').append(getString(R.string.technical_check_coverage,
                detection.getChecksSucceeded(), detection.getChecksAttempted()));
        for (String reason : detection.getFailureReasons()) {
            text.append('\n').append(getString(R.string.technical_failure_reason,
                    humanizeFailureReason(reason)));
        }
        if (detection.getDetails().isEmpty()) {
            text.append('\n').append(getString(R.string.no_abnormal_signal));
        } else {
            for (String detail : detection.getDetails()) {
                text.append("\n• ").append(humanizeEvidence(detail));
                if (!isInternalExecutionToken(detail)) {
                    text.append("\n  ").append(detail);
                }
            }
        }
        return text.toString();
    }

    private String buildRiskDescription(RiskReport report) {
        String base = getRiskDescription(report.getOverallRiskLevel());
        if (report.getReportStatus()
                != com.wsttxm.riskenginesdk.model.ReportStatus.COMPLETE) {
            base += "\n" + getString(R.string.coverage_incomplete_advice,
                    report.getIncompleteCheckCount());
        }
        for (DetectionResult detection : report.getDetections()) {
            if (detection.getStatus() != DetectionStatus.NORMAL
                    && detection.getStatus() != DetectionStatus.UNKNOWN
                    && !detection.getDetails().isEmpty()) {
                return base + "\n" + getString(R.string.primary_reason,
                        detectorTitle(detection.getDetectorName()),
                        humanizeEvidence(detection.getDetails().get(0)));
            }
        }
        return base;
    }

    private void styleLocalStatus(String label, int textColor, int backgroundColor) {
        tvLocalStatus.setText(label);
        tvLocalStatus.setTextColor(textColor);
        tvLocalStatus.setBackground(createPillDrawable(getColor(backgroundColor)));
    }

    private String detectionStatusLabel(DetectionResult detection) {
        switch (detection.getExecutionStatus()) {
            case UNAVAILABLE: return getString(R.string.execution_unavailable);
            case DISABLED: return getString(R.string.execution_disabled);
            case TIMEOUT: return getString(R.string.execution_timeout);
            case ERROR: return getString(R.string.execution_error);
            case PARTIAL:
                if (detection.getStatus() == DetectionStatus.NORMAL) {
                    return getString(R.string.execution_partial);
                }
                return getString(R.string.risk_partial,
                        getRiskLabel(detection.getRiskLevel()));
            default:
                break;
        }
        if (detection.getStatus() == DetectionStatus.NORMAL) {
            return getString(R.string.status_normal);
        }
        if (detection.isInformational()) {
            return getString(R.string.status_information);
        }
        return getRiskLabel(detection.getRiskLevel());
    }

    private String executionStatusLabel(DetectionResult detection) {
        switch (detection.getExecutionStatus()) {
            case SAFE: return getString(R.string.execution_complete);
            case RISK: return getString(R.string.execution_complete);
            case PARTIAL: return getString(R.string.execution_partial);
            case UNAVAILABLE: return getString(R.string.execution_unavailable);
            case DISABLED: return getString(R.string.execution_disabled);
            case TIMEOUT: return getString(R.string.execution_timeout);
            case ERROR:
            default: return getString(R.string.execution_error);
        }
    }

    private int detectionStatusColor(DetectionResult detection) {
        switch (detection.getExecutionStatus()) {
            case UNAVAILABLE:
            case DISABLED:
            case TIMEOUT:
            case ERROR:
                return getColor(R.color.risk_unknown);
            case PARTIAL:
                return detection.getStatus() == DetectionStatus.NORMAL
                        ? getColor(R.color.risk_unknown)
                        : getRiskColor(detection.getRiskLevel());
            default:
                return getRiskColor(detection.getRiskLevel());
        }
    }

    private int detectionStatusBackground(DetectionResult detection) {
        switch (detection.getExecutionStatus()) {
            case UNAVAILABLE:
            case DISABLED:
            case TIMEOUT:
            case ERROR:
                return R.color.unknown_bg;
            case PARTIAL:
                return detection.getStatus() == DetectionStatus.NORMAL
                        ? R.color.unknown_bg : riskBackground(detection.getRiskLevel());
            default:
                return riskBackground(detection.getRiskLevel());
        }
    }

    private String humanizeEvidence(String detail) {
        if (detail == null || detail.isBlank()) return getString(R.string.no_specific_evidence);
        if (detail.startsWith("detection_unavailable:")) {
            return getString(R.string.evidence_check_unavailable,
                    humanizeFailureReason(detail.substring("detection_unavailable:".length())));
        }
        if (isInternalExecutionToken(detail)) {
            int separator = detail.indexOf(':');
            return getString(R.string.evidence_check_unavailable,
                    humanizeFailureReason(separator >= 0
                            ? detail.substring(separator + 1) : detail));
        }
        if (detail.startsWith("settings_adb_wifi_enabled")) return getString(R.string.evidence_adb_wifi);
        if (detail.startsWith("settings_adb_enabled")) return getString(R.string.evidence_adb_usb);
        if (detail.startsWith("adb_tcp_port:")) return getString(R.string.evidence_adb_tcp);
        if (detail.startsWith("debuggable_flag")) return getString(R.string.evidence_debuggable);
        if (detail.startsWith("debugger_connected")) return getString(R.string.evidence_debugger);
        if (detail.startsWith("tracer_pid:")) return getString(R.string.evidence_tracer);
        if (detail.startsWith("su_found:")) return getString(R.string.evidence_su);
        if (detail.startsWith("magisk_found:") || detail.startsWith("native:magisk")) {
            return getString(R.string.evidence_magisk);
        }
        if (detail.startsWith("selinux_permissive")) return getString(R.string.evidence_selinux);
        if (detail.startsWith("test_keys")) return getString(R.string.evidence_test_keys);
        if (detail.contains("frida")) return getString(R.string.evidence_frida);
        if (detail.contains("xposed") || detail.contains("lsposed")) return getString(R.string.evidence_xposed);
        if (detail.startsWith("community_rom:")) return getString(R.string.evidence_custom_rom);
        if (detail.startsWith("runtime_arch:")) return getString(R.string.evidence_runtime_arch);
        if (detail.startsWith("fingerprint:") || detail.startsWith("model:")
                || detail.startsWith("hardware:") || detail.startsWith("product:")) {
            return getString(R.string.evidence_emulator_build);
        }
        if (detail.startsWith("inconsistent_fields:")) return getString(R.string.evidence_inconsistent);
        return detail.replace('_', ' ');
    }

    private boolean isInternalExecutionToken(String detail) {
        return detail.startsWith("unavailable:")
                || detail.startsWith("timeout:")
                || detail.startsWith("error:")
                || detail.startsWith("disabled:")
                || detail.startsWith("detection_unavailable:");
    }

    private String humanizeFailureReason(String reason) {
        if (reason == null || reason.isBlank()) return getString(R.string.unknown_error);
        String lower = reason.toLowerCase(Locale.ROOT);
        if (lower.contains("timeout") || lower.contains("deadline")) return getString(R.string.failure_timeout);
        if (lower.contains("securityexception")) return getString(R.string.failure_access_denied);
        if (lower.contains("native_library_unavailable") || lower.contains("native_unavailable")) {
            return getString(R.string.failure_native_unavailable);
        }
        if (lower.contains("unsupported")) return getString(R.string.failure_unsupported);
        if (lower.contains("disabled")) return getString(R.string.failure_disabled);
        return reason.replace('_', ' ');
    }

    private String detectorTitle(String name) {
        switch (name) {
            case "root": return getString(R.string.detector_root);
            case "mount_analysis": return getString(R.string.detector_mount);
            case "hook_framework": return getString(R.string.detector_hook);
            case "process_scan": return getString(R.string.detector_process);
            case "adb": return getString(R.string.detector_adb);
            case "emulator": return getString(R.string.detector_emulator);
            case "sandbox": return getString(R.string.detector_sandbox);
            case "debug": return getString(R.string.detector_debug);
            case "cloud_phone": return getString(R.string.detector_cloud_phone);
            case "custom_rom": return getString(R.string.detector_custom_rom);
            case "multi_source_validation": return getString(R.string.detector_multi_source);
            default:
                if (name.startsWith("collector:")) {
                    return getString(R.string.detector_collector_coverage,
                            collectorTitle(name.substring("collector:".length())));
                }
                return getString(R.string.detector_other);
        }
    }

    private String collectorTitle(String name) {
        switch (name) {
            case "android_id": return getString(R.string.collector_android_id);
            case "build_props": return getString(R.string.collector_build_props);
            case "screen_info": return getString(R.string.collector_screen);
            case "apk_signature": return getString(R.string.collector_signature);
            case "bluetooth_info": return getString(R.string.collector_bluetooth);
            case "wifi_info": return getString(R.string.collector_wifi);
            case "telephony": return getString(R.string.collector_telephony);
            case "settings": return getString(R.string.collector_settings);
            case "adb_state": return getString(R.string.collector_adb);
            case "container_signals": return getString(R.string.collector_container);
            case "drm_id": return getString(R.string.collector_drm);
            case "boot_id": return getString(R.string.collector_boot);
            case "system_properties_native": return getString(R.string.collector_properties);
            case "cpu_info": return getString(R.string.collector_cpu);
            case "disk_size": return getString(R.string.collector_disk);
            case "kernel_info": return getString(R.string.collector_kernel);
            case "hook_memory_signals": return getString(R.string.collector_hook_memory);
            case "runtime_integrity_score_inputs": return getString(R.string.collector_score_inputs);
            default: return getString(R.string.collector_other);
        }
    }

    private String collectorSensitivityLabel(String name) {
        if ("android_id".equals(name) || "drm_id".equals(name)
                || "boot_id".equals(name) || "apk_signature".equals(name)) {
            return getString(R.string.sensitivity_pseudonymous);
        }
        if (isSyntheticCollector(name) || "system_properties_native".equals(name)
                || "cpu_info".equals(name) || "kernel_info".equals(name)) {
            return getString(R.string.sensitivity_technical);
        }
        return getString(R.string.sensitivity_non_sensitive);
    }

    private String collectorSummary(CollectorResult result) {
        switch (result.getStatus()) {
            case EMPTY:
                return getString(R.string.collector_empty);
            case ERROR:
                return getString(R.string.collector_failed,
                        humanizeFailureReason(result.getError()));
            case UNSUPPORTED:
                return getString(R.string.collector_unsupported);
            case SUCCESS:
            default:
                if (result.isCompareSources() && result.getValues().size() > 1) {
                    return result.isConsistent()
                            ? getString(R.string.collector_sources_consistent,
                                    result.getValues().size())
                            : getString(R.string.collector_sources_inconsistent,
                                    result.getValues().size());
                }
                if (result.getValues().isEmpty()) {
                    return getString(R.string.collector_no_display_data);
                }
                StringBuilder summary = new StringBuilder();
                int count = 0;
                for (Map.Entry<String, String> entry : result.getValues().entrySet()) {
                    if (count > 0) summary.append("  ·  ");
                    summary.append(collectorValueLabel(result.getFieldName(), entry.getKey()))
                            .append("：")
                            .append(formatCollectorValue(result.getFieldName(),
                                    entry.getKey(), entry.getValue(), true));
                    if (++count == 2) break;
                }
                return summary.toString();
        }
    }

    private String collectorTechnicalDetails(CollectorResult result) {
        StringBuilder details = new StringBuilder();
        details.append(getString(R.string.collector_status_prefix,
                collectorStatusLabel(result.getStatus())));
        if (result.getError() != null && !result.getError().isBlank()) {
            details.append('\n').append(getString(R.string.collector_failure_prefix,
                    humanizeFailureReason(result.getError())));
        }
        if (result.getCanonicalValue() != null && !result.getCanonicalValue().isBlank()) {
            details.append('\n').append(getString(R.string.canonical_value_prefix,
                    formatCollectorValue(result.getFieldName(), "canonical",
                            result.getCanonicalValue(), false)));
        }
        for (Map.Entry<String, String> entry : result.getValues().entrySet()) {
            details.append("\n").append(collectorValueLabel(
                    result.getFieldName(), entry.getKey())).append("：")
                    .append(formatCollectorValue(result.getFieldName(),
                            entry.getKey(), entry.getValue(), false));
        }
        return details.toString();
    }

    private String shortenValue(String value) {
        if (value == null || value.isBlank()) {
            return getString(R.string.value_none);
        }
        String trimmed = value.trim();
        if (trimmed.length() <= 52) {
            return trimmed;
        }
        return trimmed.substring(0, 28) + "…" + trimmed.substring(trimmed.length() - 12);
    }

    private String collectorValueLabel(String field, String key) {
        switch (key) {
            case "summary": return getString(R.string.value_summary);
            case "status": return getString(R.string.value_status);
            case "supported": return getString(R.string.value_supported);
            case "low_energy_supported": return getString(R.string.value_bluetooth_le);
            case "tcp_port": return getString(R.string.value_tcp_port);
            case "signals": return getString(R.string.value_signals);
            case "count": return getString(R.string.value_count);
            case "width_px": return getString(R.string.value_width);
            case "height_px": return getString(R.string.value_height);
            case "density_dpi": return getString(R.string.value_density);
            case "native_data": return getString(R.string.value_data_capacity);
            case "native_storage": return getString(R.string.value_storage_capacity);
            case "settings_api": return getString(R.string.value_settings_api);
            case "content_resolver": return getString(R.string.value_content_resolver);
            case "content_query": return getString(R.string.value_content_query);
            default:
                if (key.startsWith("ro.")) return getString(R.string.value_system_property, key);
                return key.replace('_', ' ');
        }
    }

    private String formatCollectorValue(String field, String key, String value, boolean summary) {
        if (value == null || value.isBlank()) return getString(R.string.value_none);
        if (("disk_size".equals(field)) && ("native_data".equals(key)
                || "native_storage".equals(key))) {
            try {
                double gib = Long.parseLong(value) / (1024d * 1024d * 1024d);
                return String.format(Locale.getDefault(), "%.1f GB", gib);
            } catch (NumberFormatException ignored) {}
        }
        if ("true".equalsIgnoreCase(value)) return getString(R.string.yes);
        if ("false".equalsIgnoreCase(value)) return getString(R.string.no);
        if (summary && (field.endsWith("_id") || key.contains("hash")) && value.length() > 16) {
            return value.substring(0, 8) + "…" + value.substring(value.length() - 4);
        }
        return summary ? shortenValue(value) : value;
    }

    private String collectorStatusLabel(CollectorResult.Status status) {
        switch (status) {
            case SUCCESS: return getString(R.string.collector_status_success);
            case EMPTY: return getString(R.string.collector_status_empty);
            case ERROR: return getString(R.string.collector_status_error);
            case UNSUPPORTED: return getString(R.string.collector_status_unsupported);
            default: return getString(R.string.status_unknown);
        }
    }

    private int collectorStatusColor(CollectorResult.Status status) {
        switch (status) {
            case SUCCESS: return getColor(R.color.risk_safe);
            case ERROR: return getColor(R.color.risk_deadly);
            case EMPTY:
            case UNSUPPORTED:
            default: return getColor(R.color.risk_unknown);
        }
    }

    private int collectorStatusBackground(CollectorResult.Status status) {
        switch (status) {
            case SUCCESS: return R.color.success_bg;
            case ERROR: return R.color.danger_bg;
            case EMPTY:
            case UNSUPPORTED:
            default: return R.color.unknown_bg;
        }
    }

    private String getRiskLabel(RiskLevel level) {
        switch (level) {
            case SAFE: return getString(R.string.risk_safe);
            case LOW: return getString(R.string.risk_low);
            case MEDIUM: return getString(R.string.risk_medium);
            case HIGH: return getString(R.string.risk_high);
            case DEADLY: return getString(R.string.risk_deadly);
            case UNKNOWN:
            default: return getString(R.string.risk_unknown);
        }
    }

    private String getRiskDescription(RiskLevel level) {
        switch (level) {
            case SAFE:
                return getString(R.string.risk_description_safe);
            case LOW:
                return getString(R.string.risk_description_low);
            case MEDIUM:
                return getString(R.string.risk_description_medium);
            case HIGH:
                return getString(R.string.risk_description_high);
            case DEADLY:
                return getString(R.string.risk_description_deadly);
            case UNKNOWN:
            default:
                return getString(R.string.risk_description_unknown);
        }
    }

    private int getRiskColor(RiskLevel level) {
        switch (level) {
            case SAFE: return getColor(R.color.risk_safe);
            case LOW: return getColor(R.color.risk_low);
            case MEDIUM: return getColor(R.color.risk_medium);
            case HIGH: return getColor(R.color.risk_high);
            case DEADLY: return getColor(R.color.risk_deadly);
            case UNKNOWN:
            default: return getColor(R.color.risk_unknown);
        }
    }

    private int riskBackground(RiskLevel level) {
        switch (level) {
            case SAFE: return R.color.success_bg;
            case LOW: return R.color.unknown_bg;
            case MEDIUM:
            case HIGH: return R.color.warning_bg;
            case DEADLY: return R.color.danger_bg;
            case UNKNOWN:
            default: return R.color.unknown_bg;
        }
    }

    private TextView createStatusBadge(String text, int textColor, int backgroundColor) {
        TextView badge = createTextWithColor(text, 11, textColor, Typeface.BOLD);
        badge.setBackground(createPillDrawable(getColor(backgroundColor)));
        badge.setGravity(Gravity.CENTER);
        badge.setPadding(dp(9), dp(4), dp(9), dp(4));
        return badge;
    }

    private TextView createText(String text, int sizeSp, int colorResource, int style) {
        return createTextWithColor(text, sizeSp, getColor(colorResource), style);
    }

    private TextView createTextWithColor(String text, int sizeSp, int color, int style) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextColor(color);
        view.setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp);
        view.setTypeface(null, style);
        return view;
    }

    private View createDivider() {
        View divider = new View(this);
        divider.setBackgroundColor(getColor(R.color.divider));
        divider.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(1)));
        return divider;
    }

    private GradientDrawable createPillDrawable(int color) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setCornerRadius(dp(100));
        drawable.setColor(color);
        return drawable;
    }

    private GradientDrawable createCircleDrawable(int color) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setShape(GradientDrawable.OVAL);
        drawable.setColor(color);
        return drawable;
    }

    private String formatElapsed(long elapsedMs) {
        if (elapsedMs < 1_000) {
            return elapsedMs + "ms";
        }
        return String.format(Locale.getDefault(), "%.1fs", elapsedMs / 1_000f);
    }

    private int dp(int value) {
        return (int) TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, value, getResources().getDisplayMetrics());
    }

}
