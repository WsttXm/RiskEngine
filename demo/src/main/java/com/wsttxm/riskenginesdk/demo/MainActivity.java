package com.wsttxm.riskenginesdk.demo;

import android.animation.ValueAnimator;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.HapticFeedbackConstants;
import android.view.MotionEvent;
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
import java.text.SimpleDateFormat;
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
    private TextView tvStatDetections;
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
        installPressFeedback(btnCollect);
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
        tvStatDetections = findViewById(R.id.tvStatDetections);
        tvStatFingerprints = findViewById(R.id.tvStatFingerprints);
        tvStatElapsed = findViewById(R.id.tvStatElapsed);
        tvDetectionsHeader = findViewById(R.id.tvDetectionsHeader);
        layoutDetections = findViewById(R.id.layoutDetections);
        tvInconsistentHeader = findViewById(R.id.tvInconsistentHeader);
        layoutInconsistent = findViewById(R.id.layoutInconsistent);
        tvFingerprintHeader = findViewById(R.id.tvFingerprintHeader);
        layoutFingerprint = findViewById(R.id.layoutFingerprint);
    }

    private void initSdk() {
        if (RiskEngine.isInitialized()) {
            return;
        }
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .debugLog(BuildConfig.DEBUG)
                .collectTimeout(15_000)
                .build();
        RiskEngine.init(this, config);
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
                deliverSharedState();
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
                deliverSharedState();
            }
        };
    }

    private static void deliverSharedState() {
        MainActivity activity;
        synchronized (STATE_LOCK) {
            activity = activeActivity.get();
        }
        if (activity != null) {
            activity.runOnUiThread(activity::renderSharedState);
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
            btnCollect.performHapticFeedback(HapticFeedbackConstants.CONFIRM);
        } else if (error != null) {
            showErrorState(error);
            btnCollect.performHapticFeedback(HapticFeedbackConstants.REJECT);
        } else {
            showIdleState();
        }
    }

    private void showIdleState() {
        progressCollecting.setVisibility(View.GONE);
        tvLocalStatus.setText(R.string.status_ready_code);
        tvRiskLevel.setText(R.string.status_ready);
        tvRiskLevel.setTextColor(getColor(R.color.text_primary));
        tvStatusInfo.setText(R.string.status_ready_description);
        tvScoreCaption.setText(R.string.score_idle_description);
        progressRisk.setIndicatorColor(getColor(R.color.primary));
        progressRisk.setProgressCompat(0, false);
        layoutStats.setVisibility(View.GONE);
        tvCoverageSummary.setVisibility(View.GONE);
        btnCollect.setText(R.string.collect_action);
        btnCollect.setContentDescription(getString(R.string.collect_action));
        hideResultCards();
    }

    private void showLoadingState() {
        progressCollecting.setVisibility(View.VISIBLE);
        tvLocalStatus.setText(R.string.status_analyzing_code);
        tvRiskLevel.setText(R.string.status_analyzing);
        tvRiskLevel.setTextColor(getColor(R.color.text_primary));
        tvStatusInfo.setText(R.string.status_analyzing_description);
        tvScoreCaption.setText(R.string.score_calculating_description);
        progressRisk.setIndicatorColor(getColor(R.color.primary));
        progressRisk.setProgressCompat(0, false);
        layoutStats.setVisibility(View.GONE);
        tvCoverageSummary.setVisibility(View.GONE);
        btnCollect.setText(R.string.collecting_action);
        btnCollect.setContentDescription(getString(R.string.collecting_action));
        hideResultCards();
    }

    private void showErrorState(Throwable error) {
        progressCollecting.setVisibility(View.GONE);
        tvLocalStatus.setText(R.string.status_error_code);
        tvRiskLevel.setText(R.string.collection_failed);
        tvRiskLevel.setTextColor(getColor(R.color.risk_deadly));
        String message = error.getMessage();
        if (message == null || message.isBlank()) {
            message = getString(R.string.unknown_error);
        }
        tvStatusInfo.setText(getString(R.string.collection_failed_description, message));
        tvScoreCaption.setText(R.string.score_error_description);
        progressRisk.setIndicatorColor(getColor(R.color.risk_deadly));
        progressRisk.setProgressCompat(100, animationsEnabled());
        layoutStats.setVisibility(View.GONE);
        tvCoverageSummary.setVisibility(View.GONE);
        btnCollect.setText(R.string.retry_action);
        btnCollect.setContentDescription(getString(R.string.retry_action));
        hideResultCards();
    }

    private void displayReport(RiskReport report, long elapsedMs) {
        progressCollecting.setVisibility(View.GONE);
        RiskLevel level = report.getOverallRiskLevel();
        int riskColor = getRiskColor(level);
        tvLocalStatus.setText(level.name());
        tvRiskLevel.setText(getRiskLabel(level));
        tvRiskLevel.setTextColor(riskColor);
        tvStatusInfo.setText(getRiskDescription(level));

        int riskPercent = Math.min(100,
                Math.round((report.getRiskScore() / 18f) * 100f));
        progressRisk.setIndicatorColor(riskColor);
        progressRisk.setProgressCompat(riskPercent, animationsEnabled());

        String time = new SimpleDateFormat("HH:mm:ss", Locale.getDefault())
                .format(new Date(report.getTimestampMs()));
        tvScoreCaption.setText(String.format(Locale.getDefault(),
                "SDK %s · %s · score %d / %d",
                report.getSdkVersion(), time, report.getRiskScore(), report.getMaxRiskScore()));

        Coverage coverage = calculateCoverage(report);
        layoutStats.setVisibility(View.VISIBLE);
        tvStatDetections.setText(String.valueOf(report.getRiskScore()));
        tvStatFingerprints.setText(getString(R.string.coverage_percent, coverage.percent));
        tvStatElapsed.setText(formatElapsed(elapsedMs));
        tvCoverageSummary.setVisibility(View.VISIBLE);
        tvCoverageSummary.setText(String.format(Locale.getDefault(),
                "完成 %d / %d 项 · 未知 %d 项 · 采集字段 %d 项",
                coverage.completed, coverage.total, coverage.unknown,
                report.getFingerprint().getResults().size()));

        btnCollect.setText(R.string.collect_again_action);
        btnCollect.setContentDescription(getString(R.string.collect_again_action));
        displayDetections(report);
        displayInconsistentFields(report);
        displayFingerprint(report);
    }

    private Coverage calculateCoverage(RiskReport report) {
        int detectorChecks = 0;
        for (DetectionResult detection : report.getDetections()) {
            if (!detection.getDetectorName().startsWith("collector:")) {
                detectorChecks++;
            }
        }

        int collectorChecks = 0;
        for (String name : report.getFingerprint().getResults().keySet()) {
            if (!"hook_memory_signals".equals(name)
                    && !"runtime_integrity_score_inputs".equals(name)) {
                collectorChecks++;
            }
        }
        int total = Math.max(1, detectorChecks + collectorChecks);
        int unknown = Math.min(total, report.getUnknownCount());
        int completed = total - unknown;
        int percent = Math.round((completed * 100f) / total);
        return new Coverage(total, completed, unknown, percent);
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
        tvDetectionsHeader.setText(String.format(Locale.getDefault(),
                "环境检测 · %d 项 · %d 项需关注", detections.size(), attentionCount));

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

        LinearLayout header = new LinearLayout(this);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setOrientation(LinearLayout.HORIZONTAL);

        View dot = new View(this);
        LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(dp(9), dp(9));
        dotParams.rightMargin = dp(11);
        dot.setLayoutParams(dotParams);
        dot.setBackground(createCircleDrawable(getRiskColor(detection.getRiskLevel())));
        header.addView(dot);

        LinearLayout titleGroup = new LinearLayout(this);
        titleGroup.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        titleGroup.setLayoutParams(titleParams);

        TextView title = createText(detectorTitle(detection.getDetectorName()),
                14, R.color.text_primary, Typeface.BOLD);
        titleGroup.addView(title);
        TextView technicalName = createText(detection.getDetectorName(),
                11, R.color.text_tertiary, Typeface.NORMAL);
        technicalName.setTypeface(Typeface.MONOSPACE);
        titleGroup.addView(technicalName);
        header.addView(titleGroup);

        TextView badge = createStatusBadge(
                getRiskLabel(detection.getRiskLevel()),
                getRiskColor(detection.getRiskLevel()),
                riskBackground(detection.getRiskLevel()));
        header.addView(badge);

        TextView disclosure = createText(getString(R.string.expand_details),
                11, R.color.text_tertiary, Typeface.NORMAL);
        disclosure.setPadding(dp(8), 0, 0, 0);
        header.addView(disclosure);
        row.addView(header);

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
        TextView detailLabel = createText("技术证据 · Technical Evidence",
                11, R.color.text_tertiary, Typeface.BOLD);
        details.addView(detailLabel);
        TextView evidence = createText(normalizeEvidence(detection.getEvidence()),
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

        row.setContentDescription(detectorTitle(detection.getDetectorName())
                + "，" + getRiskLabel(detection.getRiskLevel()) + "，轻触查看详情");
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

        tvInconsistentHeader.setText(String.format(Locale.getDefault(),
                "数据一致性提醒 · %d 项", inconsistent.size()));
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

        int unavailable = 0;
        for (CollectorResult result : results.values()) {
            if (result.getStatus() != CollectorResult.Status.SUCCESS) {
                unavailable++;
            }
        }
        tvFingerprintHeader.setText(String.format(Locale.getDefault(),
                "数据采集 · %d 项 · %d 项无可用数据", results.size(), unavailable));

        int index = 0;
        for (CollectorResult result : results.values()) {
            layoutFingerprint.addView(createFingerprintRow(result));
            if (index < results.size() - 1) {
                layoutFingerprint.addView(createDivider());
            }
            index++;
        }
        revealCard(cardFingerprint, 2);
    }

    private View createFingerprintRow(CollectorResult result) {
        LinearLayout row = createInteractiveRow();
        LinearLayout header = new LinearLayout(this);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setOrientation(LinearLayout.HORIZONTAL);

        LinearLayout titleGroup = new LinearLayout(this);
        titleGroup.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        titleGroup.setLayoutParams(titleParams);
        titleGroup.addView(createText(collectorTitle(result.getFieldName()),
                14, R.color.text_primary, Typeface.BOLD));
        TextView technicalName = createText(result.getFieldName(),
                11, R.color.text_tertiary, Typeface.NORMAL);
        technicalName.setTypeface(Typeface.MONOSPACE);
        titleGroup.addView(technicalName);
        header.addView(titleGroup);

        int statusColor = collectorStatusColor(result.getStatus());
        TextView badge = createStatusBadge(
                collectorStatusLabel(result.getStatus()),
                statusColor,
                collectorStatusBackground(result.getStatus()));
        header.addView(badge);

        TextView disclosure = createText(getString(R.string.expand_details),
                11, R.color.text_tertiary, Typeface.NORMAL);
        disclosure.setPadding(dp(8), 0, 0, 0);
        header.addView(disclosure);
        row.addView(header);

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
        TextView detailLabel = createText("来源详情 · Source Values",
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

        row.setContentDescription(collectorTitle(result.getFieldName())
                + "，" + collectorStatusLabel(result.getStatus()) + "，轻触查看详情");
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

    private void installPressFeedback(View view) {
        view.setOnTouchListener((target, event) -> {
            switch (event.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    target.setPressed(true);
                    animateScale(target, 0.97f, 80);
                    break;
                case MotionEvent.ACTION_MOVE:
                    int allowance = dp(10);
                    boolean inside = event.getX() >= -allowance
                            && event.getY() >= -allowance
                            && event.getX() <= target.getWidth() + allowance
                            && event.getY() <= target.getHeight() + allowance;
                    target.setPressed(inside);
                    animateScale(target, inside ? 0.97f : 1f, 80);
                    break;
                case MotionEvent.ACTION_UP: {
                    boolean shouldClick = target.isPressed();
                    target.setPressed(false);
                    animateScale(target, 1f, 180);
                    if (shouldClick) {
                        target.performClick();
                    }
                    break;
                }
                case MotionEvent.ACTION_CANCEL:
                    target.setPressed(false);
                    animateScale(target, 1f, 180);
                    break;
                default:
                    break;
            }
            return true;
        });
    }

    private void animateScale(View view, float scale, long durationMs) {
        view.animate().cancel();
        if (!animationsEnabled()) {
            view.setScaleX(scale);
            view.setScaleY(scale);
            return;
        }
        view.animate()
                .scaleX(scale)
                .scaleY(scale)
                .setDuration(durationMs)
                .setInterpolator(new DecelerateInterpolator())
                .start();
    }

    private boolean animationsEnabled() {
        return ValueAnimator.areAnimatorsEnabled();
    }

    private int detectionPriority(DetectionResult detection) {
        switch (detection.getStatus()) {
            case DANGER:
                return detection.isWarnOnly() ? 1 : 0;
            case WARNING:
                return detection.isWarnOnly() ? 3 : 2;
            case UNKNOWN:
                return 4;
            case NORMAL:
            default:
                return 5;
        }
    }

    private String detectionSummary(DetectionResult detection) {
        if (detection.getStatus() == DetectionStatus.UNKNOWN) {
            return "检测未完成，已计入覆盖不足；这不代表当前环境安全。";
        }
        if (detection.getStatus() == DetectionStatus.NORMAL) {
            return "未发现异常信号。";
        }
        if (detection.isWarnOnly()) {
            return "发现提示性信号，单独出现时不会提高综合风险等级。";
        }
        if (detection.getStatus() == DetectionStatus.DANGER) {
            return "发现高置信度风险信号，建议结合技术证据进一步处置。";
        }
        return "发现需要关注的环境信号，建议结合业务场景复核。";
    }

    private String normalizeEvidence(String evidence) {
        if (evidence == null || evidence.isBlank() || "no risk detected".equals(evidence)) {
            return "none · 未发现异常";
        }
        return evidence;
    }

    private String detectorTitle(String name) {
        switch (name) {
            case "root": return "Root 权限风险";
            case "mount_analysis": return "系统挂载完整性";
            case "hook_framework": return "注入与 Hook";
            case "process_scan": return "可疑进程";
            case "adb": return "ADB 调试桥";
            case "emulator": return "模拟器环境";
            case "sandbox": return "沙箱与虚拟化";
            case "debug": return "调试器连接";
            case "cloud_phone": return "云手机特征";
            case "custom_rom": return "第三方 ROM";
            case "multi_source_validation": return "多源一致性";
            default:
                if (name.startsWith("collector:")) {
                    return "采集覆盖 · " + collectorTitle(name.substring("collector:".length()));
                }
                return "其他检测";
        }
    }

    private String collectorTitle(String name) {
        switch (name) {
            case "android_id": return "Android 标识哈希";
            case "build_props": return "系统构建信息";
            case "screen_info": return "屏幕特征";
            case "apk_signature": return "应用签名";
            case "bluetooth_info": return "蓝牙能力";
            case "wifi_info": return "Wi-Fi 能力";
            case "telephony": return "通信能力";
            case "settings": return "安全设置摘要";
            case "adb_state": return "ADB 状态";
            case "container_signals": return "容器信号";
            case "drm_id": return "DRM 标识哈希";
            case "boot_id": return "启动标识哈希";
            case "system_properties_native": return "系统属性";
            case "cpu_info": return "CPU 信息";
            case "disk_size": return "存储容量";
            case "kernel_info": return "内核信息";
            case "hook_memory_signals": return "Hook 内存信号";
            case "runtime_integrity_score_inputs": return "风险评分输入";
            default: return "其他采集项";
        }
    }

    private String collectorSummary(CollectorResult result) {
        switch (result.getStatus()) {
            case EMPTY:
                return "当前环境未返回可展示数据。";
            case ERROR:
                return "采集失败 · " + safeReason(result.getError());
            case UNSUPPORTED:
                return "当前设备或运行环境不支持此采集项。";
            case SUCCESS:
            default:
                if (result.isCompareSources() && result.getValues().size() > 1) {
                    return result.isConsistent()
                            ? result.getValues().size() + " 个来源结果一致"
                            : result.getValues().size() + " 个来源结果不一致";
                }
                if (result.getValues().isEmpty()) {
                    return "采集完成，未返回可展示数据。";
                }
                StringBuilder summary = new StringBuilder();
                int count = 0;
                for (Map.Entry<String, String> entry : result.getValues().entrySet()) {
                    if (count > 0) summary.append("  ·  ");
                    summary.append(entry.getKey()).append(" = ")
                            .append(shortenValue(entry.getValue()));
                    if (++count == 2) break;
                }
                return summary.toString();
        }
    }

    private String collectorTechnicalDetails(CollectorResult result) {
        StringBuilder details = new StringBuilder();
        details.append("status = ").append(result.getStatus());
        if (result.getError() != null && !result.getError().isBlank()) {
            details.append("\nreason = ").append(result.getError());
        }
        for (Map.Entry<String, String> entry : result.getValues().entrySet()) {
            details.append("\n").append(entry.getKey()).append(" = ")
                    .append(entry.getValue());
        }
        return details.toString();
    }

    private String shortenValue(String value) {
        if (value == null || value.isBlank()) {
            return "无数据";
        }
        String trimmed = value.trim();
        if (trimmed.length() <= 52) {
            return trimmed;
        }
        return trimmed.substring(0, 28) + "…" + trimmed.substring(trimmed.length() - 12);
    }

    private String safeReason(String reason) {
        return reason == null || reason.isBlank() ? "unknown" : reason;
    }

    private String collectorStatusLabel(CollectorResult.Status status) {
        switch (status) {
            case SUCCESS: return "已采集";
            case EMPTY: return "无数据";
            case ERROR: return "失败";
            case UNSUPPORTED: return "不支持";
            default: return "未知";
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
            case SAFE: return "安全";
            case LOW: return "低风险";
            case MEDIUM: return "中风险";
            case HIGH: return "高风险";
            case DEADLY: return "严重风险";
            case UNKNOWN:
            default: return "覆盖不足";
        }
    }

    private String getRiskDescription(RiskLevel level) {
        switch (level) {
            case SAFE:
                return "已完成的检测中未发现需要处置的环境风险。";
            case LOW:
                return "发现少量提示性信号，建议结合当前设备与业务场景判断。";
            case MEDIUM:
                return "发现需要关注的环境信号，建议查看检测详情后复核。";
            case HIGH:
                return "发现高置信度风险信号，建议限制敏感操作并进一步检查。";
            case DEADLY:
                return "发现严重运行环境风险，建议立即停止敏感流程并处置。";
            case UNKNOWN:
            default:
                return "部分检测未完成，当前结果不能被解释为安全。";
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

    private static final class Coverage {
        private final int total;
        private final int completed;
        private final int unknown;
        private final int percent;

        private Coverage(int total, int completed, int unknown, int percent) {
            this.total = total;
            this.completed = completed;
            this.unknown = unknown;
            this.percent = percent;
        }
    }
}
