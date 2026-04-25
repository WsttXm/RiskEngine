package com.wsttxm.riskenginesdk.demo;

import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.wsttxm.riskenginesdk.RiskEngine;
import com.wsttxm.riskenginesdk.RiskEngineCallback;
import com.wsttxm.riskenginesdk.RiskEngineConfig;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.model.RiskReport;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;

public class MainActivity extends AppCompatActivity {

    private MaterialButton btnCollect;
    private MaterialCardView cardStatus;
    private MaterialCardView cardDetections;
    private MaterialCardView cardInconsistent;
    private MaterialCardView cardFingerprint;

    private TextView tvRiskLevel;
    private TextView tvStatusInfo;
    private TextView tvLocalStatus;
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

    private boolean collecting = false;
    private long collectStartTime;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initViews();
        initSdk();

        btnCollect.setOnClickListener(v -> doCollect());

        // Auto-collect on launch
        doCollect();
    }

    private void initViews() {
        btnCollect = findViewById(R.id.btnCollect);
        cardStatus = findViewById(R.id.cardStatus);
        cardDetections = findViewById(R.id.cardDetections);
        cardInconsistent = findViewById(R.id.cardInconsistent);
        cardFingerprint = findViewById(R.id.cardFingerprint);
        tvRiskLevel = findViewById(R.id.tvRiskLevel);
        tvStatusInfo = findViewById(R.id.tvStatusInfo);
        tvLocalStatus = findViewById(R.id.tvLocalStatus);
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
        RiskEngineConfig.Builder builder = new RiskEngineConfig.Builder()
                .debugLog(true)
                .collectTimeout(15000);

        RiskEngine.init(this, builder.build());
    }

    private void doCollect() {
        if (collecting) {
            Toast.makeText(this, "正在采集中...", Toast.LENGTH_SHORT).show();
            return;
        }

        collecting = true;
        collectStartTime = System.currentTimeMillis();
        btnCollect.setEnabled(false);
        btnCollect.setText("采集中...");

        // Show status card with loading state
        cardStatus.setVisibility(View.VISIBLE);
        tvRiskLevel.setText("...");
        tvRiskLevel.setTextColor(getColor(R.color.text_tertiary));
        tvStatusInfo.setText("正在采集设备信息...");
        layoutStats.setVisibility(View.GONE);

        // Hide result cards
        cardDetections.setVisibility(View.GONE);
        cardInconsistent.setVisibility(View.GONE);
        cardFingerprint.setVisibility(View.GONE);

        RiskEngine.collect(new RiskEngineCallback() {
            @Override
            public void onSuccess(RiskReport report) {
                runOnUiThread(() -> {
                    long elapsed = System.currentTimeMillis() - collectStartTime;
                    displayReport(report, elapsed);
                    collecting = false;
                    btnCollect.setEnabled(true);
                    btnCollect.setText("重新采集");
                });
            }

            @Override
            public void onError(Throwable error) {
                runOnUiThread(() -> {
                    tvRiskLevel.setText("ERROR");
                    tvRiskLevel.setTextColor(getColor(R.color.risk_deadly));
                    tvStatusInfo.setText("采集失败: " + error.getMessage());
                    collecting = false;
                    btnCollect.setEnabled(true);
                    btnCollect.setText("重试");
                });
            }
        });
    }

    private void displayReport(RiskReport report, long elapsedMs) {
        // Risk Level
        RiskLevel level = report.getOverallRiskLevel();
        tvRiskLevel.setText(level.name());
        tvRiskLevel.setTextColor(getRiskColor(level));

        // Status info
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());
        String time = sdf.format(new Date(report.getTimestampMs()));
        int detectionCount = report.getDetections().size();
        int fingerprintCount = report.getFingerprint().getResults().size();
        tvStatusInfo.setText(String.format(Locale.getDefault(),
                "SDK %s · %s", report.getSdkVersion(), time));

        // Stats
        layoutStats.setVisibility(View.VISIBLE);
        tvStatDetections.setText(String.valueOf(detectionCount));
        tvStatFingerprints.setText(String.valueOf(fingerprintCount));
        tvStatElapsed.setText(String.valueOf(elapsedMs));

        // Detection Results
        displayDetections(report);

        // Inconsistent Fields
        displayInconsistentFields(report);

        // Device Fingerprint
        displayFingerprint(report);
    }

    private void displayDetections(RiskReport report) {
        layoutDetections.removeAllViews();

        int total = report.getDetections().size();
        if (total == 0) {
            cardDetections.setVisibility(View.GONE);
            return;
        }

        cardDetections.setVisibility(View.VISIBLE);
        tvDetectionsHeader.setText("环境检测  ·  " + total + " 项");

        int idx = 0;
        for (DetectionResult dr : report.getDetections()) {
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.VERTICAL);
            row.setPadding(0, dp(10), 0, dp(10));

            // Name + Risk Level Row
            LinearLayout nameRow = new LinearLayout(this);
            nameRow.setOrientation(LinearLayout.HORIZONTAL);
            nameRow.setGravity(Gravity.CENTER_VERTICAL);

            // Risk dot
            View dot = new View(this);
            LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(dp(8), dp(8));
            dotParams.rightMargin = dp(10);
            dot.setLayoutParams(dotParams);
            dot.setBackground(createCircleDrawable(getRiskColor(dr.getRiskLevel())));
            nameRow.addView(dot);

            // Detector name
            TextView name = new TextView(this);
            name.setText(dr.getDetectorName());
            name.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
            name.setTextColor(getColor(R.color.text_primary));
            name.setTypeface(null, Typeface.BOLD);
            LinearLayout.LayoutParams nameParams = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
            name.setLayoutParams(nameParams);
            nameRow.addView(name);

            // Risk level badge
            TextView badge = new TextView(this);
            badge.setText(dr.getRiskLevel().name());
            badge.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
            badge.setTextColor(Color.WHITE);
            badge.setTypeface(null, Typeface.BOLD);
            badge.setPadding(dp(8), dp(3), dp(8), dp(3));
            badge.setBackground(createPillDrawable(getRiskColor(dr.getRiskLevel())));
            badge.setLetterSpacing(0.05f);
            nameRow.addView(badge);

            row.addView(nameRow);

            // Evidence
            if (dr.getEvidence() != null && !dr.getEvidence().isEmpty()) {
                TextView evidence = new TextView(this);
                evidence.setText(dr.getEvidence());
                evidence.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
                evidence.setTextColor(getColor(R.color.text_secondary));
                LinearLayout.LayoutParams evidenceParams = new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
                evidenceParams.leftMargin = dp(18);
                evidenceParams.topMargin = dp(3);
                evidence.setLayoutParams(evidenceParams);
                row.addView(evidence);
            }

            layoutDetections.addView(row);

            // Divider (except last)
            if (idx < total - 1) {
                View divider = new View(this);
                divider.setBackgroundColor(getColor(R.color.divider));
                LinearLayout.LayoutParams divParams = new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT, dp(1));
                divider.setLayoutParams(divParams);
                layoutDetections.addView(divider);
            }
            idx++;
        }
    }

    private void displayInconsistentFields(RiskReport report) {
        layoutInconsistent.removeAllViews();

        if (!report.getFingerprint().hasInconsistency()) {
            cardInconsistent.setVisibility(View.GONE);
            return;
        }

        cardInconsistent.setVisibility(View.VISIBLE);
        int count = report.getFingerprint().getInconsistentFields().size();
        tvInconsistentHeader.setText("⚠  发现 " + count + " 项不一致字段");

        for (String field : report.getFingerprint().getInconsistentFields()) {
            TextView tv = new TextView(this);
            tv.setText("• " + field);
            tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
            tv.setTextColor(getColor(R.color.inconsistent_text));
            tv.setTypeface(null, Typeface.BOLD);
            tv.setPadding(0, dp(6), 0, dp(2));
            layoutInconsistent.addView(tv);

            CollectorResult cr = report.getFingerprint().getResults().get(field);
            if (cr != null) {
                for (Map.Entry<String, String> entry : cr.getValues().entrySet()) {
                    TextView val = new TextView(this);
                    String value = entry.getValue();
                    if (value == null || value.isEmpty()) value = "(empty)";
                    val.setText("    " + entry.getKey() + " = " + value);
                    val.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
                    val.setTextColor(getColor(R.color.inconsistent_text));
                    val.setTypeface(Typeface.MONOSPACE);
                    val.setAlpha(0.85f);
                    layoutInconsistent.addView(val);
                }
            }
        }
    }

    private void displayFingerprint(RiskReport report) {
        layoutFingerprint.removeAllViews();

        int totalFields = report.getFingerprint().getResults().size();
        if (totalFields == 0) {
            cardFingerprint.setVisibility(View.GONE);
            return;
        }

        cardFingerprint.setVisibility(View.VISIBLE);
        tvFingerprintHeader.setText("设备指纹  ·  " + totalFields + " 项");

        int idx = 0;
        for (Map.Entry<String, CollectorResult> entry :
                report.getFingerprint().getResults().entrySet()) {
            CollectorResult cr = entry.getValue();

            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.VERTICAL);
            row.setPadding(0, dp(10), 0, dp(10));

            // Header row: field name + methods chip + inconsistent flag
            LinearLayout headerRow = new LinearLayout(this);
            headerRow.setOrientation(LinearLayout.HORIZONTAL);
            headerRow.setGravity(Gravity.CENTER_VERTICAL);

            TextView fieldName = new TextView(this);
            fieldName.setText(cr.getFieldName());
            fieldName.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
            fieldName.setTextColor(getColor(R.color.text_primary));
            fieldName.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
            LinearLayout.LayoutParams nameParams = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
            fieldName.setLayoutParams(nameParams);
            headerRow.addView(fieldName);

            if (!cr.isConsistent()) {
                TextView warn = new TextView(this);
                warn.setText("⚠");
                warn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
                warn.setTextColor(getColor(R.color.risk_medium));
                warn.setPadding(0, 0, dp(6), 0);
                headerRow.addView(warn);
            }

            TextView methodCount = new TextView(this);
            methodCount.setText(cr.getValues().size() + " 法");
            methodCount.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
            methodCount.setTextColor(getColor(R.color.accent));
            methodCount.setBackground(getDrawable(R.drawable.bg_pill_subtle));
            methodCount.setPadding(dp(8), dp(2), dp(8), dp(2));
            methodCount.setTypeface(null, Typeface.BOLD);
            headerRow.addView(methodCount);

            row.addView(headerRow);

            // Canonical value
            String canonical = cr.getCanonicalValue();
            if (canonical == null || canonical.isEmpty()) canonical = "(empty)";
            TextView canonicalView = new TextView(this);
            canonicalView.setText(canonical);
            canonicalView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
            canonicalView.setTextColor(getColor(R.color.text_secondary));
            canonicalView.setTypeface(Typeface.MONOSPACE);
            canonicalView.setMaxLines(2);
            canonicalView.setEllipsize(android.text.TextUtils.TruncateAt.END);
            LinearLayout.LayoutParams canonicalParams = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
            canonicalParams.topMargin = dp(4);
            canonicalView.setLayoutParams(canonicalParams);
            row.addView(canonicalView);

            layoutFingerprint.addView(row);

            // Divider (except last)
            if (idx < totalFields - 1) {
                View divider = new View(this);
                divider.setBackgroundColor(getColor(R.color.divider));
                LinearLayout.LayoutParams divParams = new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT, dp(1));
                divider.setLayoutParams(divParams);
                layoutFingerprint.addView(divider);
            }
            idx++;
        }
    }

    private int getRiskColor(RiskLevel level) {
        switch (level) {
            case SAFE: return getColor(R.color.risk_safe);
            case LOW: return getColor(R.color.risk_low);
            case MEDIUM: return getColor(R.color.risk_medium);
            case HIGH: return getColor(R.color.risk_high);
            case DEADLY: return getColor(R.color.risk_deadly);
            default: return getColor(R.color.text_secondary);
        }
    }

    private android.graphics.drawable.GradientDrawable createPillDrawable(int color) {
        android.graphics.drawable.GradientDrawable drawable = new android.graphics.drawable.GradientDrawable();
        drawable.setCornerRadius(dp(100));
        drawable.setColor(color);
        return drawable;
    }

    private android.graphics.drawable.GradientDrawable createCircleDrawable(int color) {
        android.graphics.drawable.GradientDrawable drawable = new android.graphics.drawable.GradientDrawable();
        drawable.setShape(android.graphics.drawable.GradientDrawable.OVAL);
        drawable.setColor(color);
        return drawable;
    }

    private int dp(int value) {
        return (int) TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, value, getResources().getDisplayMetrics());
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        RiskEngine.shutdown();
    }
}
