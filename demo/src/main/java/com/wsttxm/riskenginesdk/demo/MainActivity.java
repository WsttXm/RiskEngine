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
    private MaterialCardView cardJson;

    private TextView tvRiskLevel;
    private TextView tvStatusInfo;
    private TextView tvLocalStatus;
    private LinearLayout layoutDetections;
    private TextView tvInconsistentHeader;
    private LinearLayout layoutInconsistent;
    private TextView tvFingerprintHeader;
    private LinearLayout layoutFingerprint;
    private TextView tvJsonData;

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
        cardJson = findViewById(R.id.cardJson);
        tvRiskLevel = findViewById(R.id.tvRiskLevel);
        tvStatusInfo = findViewById(R.id.tvStatusInfo);
        tvLocalStatus = findViewById(R.id.tvLocalStatus);
        layoutDetections = findViewById(R.id.layoutDetections);
        tvInconsistentHeader = findViewById(R.id.tvInconsistentHeader);
        layoutInconsistent = findViewById(R.id.layoutInconsistent);
        tvFingerprintHeader = findViewById(R.id.tvFingerprintHeader);
        layoutFingerprint = findViewById(R.id.layoutFingerprint);
        tvJsonData = findViewById(R.id.tvJsonData);
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

        // Show status card with loading state
        cardStatus.setVisibility(View.VISIBLE);
        tvRiskLevel.setText("...");
        tvRiskLevel.setTextColor(getColor(R.color.text_secondary));
        tvStatusInfo.setText("正在采集设备信息...");
        tvLocalStatus.setVisibility(View.VISIBLE);
        tvLocalStatus.setText("仅本地采集，不进行网络传输");
        tvLocalStatus.setTextColor(getColor(R.color.text_secondary));

        // Hide result cards
        cardDetections.setVisibility(View.GONE);
        cardInconsistent.setVisibility(View.GONE);
        cardFingerprint.setVisibility(View.GONE);
        cardJson.setVisibility(View.GONE);

        RiskEngine.collect(new RiskEngineCallback() {
            @Override
            public void onSuccess(RiskReport report) {
                runOnUiThread(() -> {
                    long elapsed = System.currentTimeMillis() - collectStartTime;
                    displayReport(report, elapsed);
                    collecting = false;
                    btnCollect.setEnabled(true);
                });
            }

            @Override
            public void onError(Throwable error) {
                runOnUiThread(() -> {
                    tvRiskLevel.setText("ERROR");
                    tvRiskLevel.setTextColor(getColor(R.color.risk_deadly));
                    tvStatusInfo.setText("采集失败: " + error.getMessage());
                    tvLocalStatus.setVisibility(View.GONE);
                    collecting = false;
                    btnCollect.setEnabled(true);
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
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
        String time = sdf.format(new Date(report.getTimestampMs()));
        int detectionCount = report.getDetections().size();
        int fingerprintCount = report.getFingerprint().getResults().size();
        tvStatusInfo.setText(String.format(Locale.getDefault(),
                "SDK %s | %s | 耗时 %dms\n采集 %d 项指纹, %d 项检测",
                report.getSdkVersion(), time, elapsedMs, fingerprintCount, detectionCount));

        tvLocalStatus.setText("采集完成，结果仅保存在当前进程内");
        tvLocalStatus.setTextColor(getColor(R.color.text_secondary));

        // Detection Results
        displayDetections(report);

        // Inconsistent Fields
        displayInconsistentFields(report);

        // Device Fingerprint
        displayFingerprint(report);

        // Raw JSON
        displayRawJson(report);
    }

    private void displayDetections(RiskReport report) {
        layoutDetections.removeAllViews();
        cardDetections.setVisibility(View.VISIBLE);

        for (DetectionResult dr : report.getDetections()) {
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.VERTICAL);
            row.setPadding(0, 0, 0, dp(8));

            // Name + Risk Level Row
            LinearLayout nameRow = new LinearLayout(this);
            nameRow.setOrientation(LinearLayout.HORIZONTAL);
            nameRow.setGravity(Gravity.CENTER_VERTICAL);

            // Risk dot
            TextView dot = new TextView(this);
            dot.setText("\u25CF ");
            dot.setTextColor(getRiskColor(dr.getRiskLevel()));
            dot.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
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
            badge.setText(" " + dr.getRiskLevel().name() + " ");
            badge.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
            badge.setTextColor(Color.WHITE);
            badge.setTypeface(null, Typeface.BOLD);
            badge.setPadding(dp(6), dp(2), dp(6), dp(2));
            badge.setBackground(createRiskBadgeDrawable(dr.getRiskLevel()));
            nameRow.addView(badge);

            row.addView(nameRow);

            // Evidence
            if (dr.getEvidence() != null && !dr.getEvidence().isEmpty()) {
                TextView evidence = new TextView(this);
                evidence.setText(dr.getEvidence());
                evidence.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
                evidence.setTextColor(getColor(R.color.text_secondary));
                evidence.setPadding(dp(16), dp(2), 0, 0);
                row.addView(evidence);
            }

            layoutDetections.addView(row);

            // Divider (except last)
            if (report.getDetections().indexOf(dr) < report.getDetections().size() - 1) {
                View divider = new View(this);
                divider.setBackgroundColor(getColor(R.color.divider));
                LinearLayout.LayoutParams divParams = new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT, dp(1));
                divParams.bottomMargin = dp(8);
                divider.setLayoutParams(divParams);
                layoutDetections.addView(divider);
            }
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
        tvInconsistentHeader.setText("不一致字段 (" + count + " 项)");

        for (String field : report.getFingerprint().getInconsistentFields()) {
            TextView tv = new TextView(this);
            tv.setText("\u26A0 " + field);
            tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
            tv.setTextColor(Color.parseColor("#856404"));
            tv.setPadding(0, dp(2), 0, dp(2));
            layoutInconsistent.addView(tv);

            // Show the inconsistent values
            CollectorResult cr = report.getFingerprint().getResults().get(field);
            if (cr != null) {
                for (Map.Entry<String, String> entry : cr.getValues().entrySet()) {
                    TextView val = new TextView(this);
                    val.setText("  " + entry.getKey() + " = " + entry.getValue());
                    val.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
                    val.setTextColor(getColor(R.color.text_secondary));
                    val.setFontFeatureSettings("monospace");
                    layoutInconsistent.addView(val);
                }
            }
        }
    }

    private void displayFingerprint(RiskReport report) {
        layoutFingerprint.removeAllViews();
        cardFingerprint.setVisibility(View.VISIBLE);

        int totalFields = report.getFingerprint().getResults().size();
        int totalValues = 0;
        for (CollectorResult cr : report.getFingerprint().getResults().values()) {
            totalValues += cr.getValues().size();
        }
        tvFingerprintHeader.setText("设备指纹 (" + totalFields + " 项, " + totalValues + " 个采集点)");

        for (Map.Entry<String, CollectorResult> entry :
                report.getFingerprint().getResults().entrySet()) {
            CollectorResult cr = entry.getValue();

            // Field name header
            LinearLayout fieldHeader = new LinearLayout(this);
            fieldHeader.setOrientation(LinearLayout.HORIZONTAL);
            fieldHeader.setGravity(Gravity.CENTER_VERTICAL);
            fieldHeader.setPadding(0, dp(6), 0, dp(2));

            TextView fieldName = new TextView(this);
            fieldName.setText(cr.getFieldName());
            fieldName.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
            fieldName.setTextColor(getColor(R.color.accent));
            fieldName.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
            fieldHeader.addView(fieldName);

            if (!cr.isConsistent()) {
                TextView warn = new TextView(this);
                warn.setText("  \u26A0 INCONSISTENT");
                warn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
                warn.setTextColor(getColor(R.color.risk_medium));
                warn.setTypeface(null, Typeface.BOLD);
                fieldHeader.addView(warn);
            }

            // Methods count
            TextView methodCount = new TextView(this);
            methodCount.setText("  (" + cr.getValues().size() + " methods)");
            methodCount.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
            methodCount.setTextColor(getColor(R.color.text_secondary));
            fieldHeader.addView(methodCount);

            layoutFingerprint.addView(fieldHeader);

            // Canonical value
            if (cr.getCanonicalValue() != null) {
                TextView canonical = new TextView(this);
                canonical.setText("  = " + cr.getCanonicalValue());
                canonical.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
                canonical.setTextColor(getColor(R.color.text_primary));
                canonical.setTypeface(Typeface.MONOSPACE);
                layoutFingerprint.addView(canonical);
            }

            // All method values (detailed)
            for (Map.Entry<String, String> val : cr.getValues().entrySet()) {
                TextView methodVal = new TextView(this);
                String value = val.getValue();
                if (value == null || value.isEmpty()) value = "(empty)";
                methodVal.setText("    " + val.getKey() + ": " + value);
                methodVal.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
                methodVal.setTextColor(getColor(R.color.text_secondary));
                methodVal.setTypeface(Typeface.MONOSPACE);
                layoutFingerprint.addView(methodVal);
            }

            // Divider
            View divider = new View(this);
            divider.setBackgroundColor(getColor(R.color.divider));
            LinearLayout.LayoutParams divParams = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, dp(1));
            divParams.topMargin = dp(4);
            divider.setLayoutParams(divParams);
            layoutFingerprint.addView(divider);
        }
    }

    private void displayRawJson(RiskReport report) {
        cardJson.setVisibility(View.VISIBLE);
        try {
            com.google.gson.Gson gson = new com.google.gson.GsonBuilder()
                    .setPrettyPrinting()
                    .disableHtmlEscaping()
                    .create();
            tvJsonData.setText(gson.toJson(report));
        } catch (Exception e) {
            tvJsonData.setText("Failed to serialize: " + e.getMessage());
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

    private android.graphics.drawable.GradientDrawable createRiskBadgeDrawable(RiskLevel level) {
        android.graphics.drawable.GradientDrawable drawable = new android.graphics.drawable.GradientDrawable();
        drawable.setCornerRadius(dp(4));
        drawable.setColor(getRiskColor(level));
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
