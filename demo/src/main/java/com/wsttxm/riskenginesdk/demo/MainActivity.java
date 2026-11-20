package com.wsttxm.riskenginesdk.demo;

import android.animation.ValueAnimator;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.res.Configuration;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.HapticFeedbackConstants;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.activity.OnBackPressedCallback;
import androidx.annotation.ColorInt;
import androidx.annotation.ColorRes;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;
import androidx.dynamicanimation.animation.DynamicAnimation;
import androidx.dynamicanimation.animation.SpringAnimation;
import androidx.dynamicanimation.animation.SpringForce;

import com.google.android.material.button.MaterialButton;
import com.wsttxm.riskenginesdk.RiskEngine;
import com.wsttxm.riskenginesdk.RiskEngineCallback;
import com.wsttxm.riskenginesdk.RiskEngineConfig;
import com.wsttxm.riskenginesdk.demo.ui.FluidDetailSheet;
import com.wsttxm.riskenginesdk.demo.ui.ReportFormatter;
import com.wsttxm.riskenginesdk.demo.ui.RiskGaugeView;
import com.wsttxm.riskenginesdk.demo.ui.SegmentedControlView;
import com.wsttxm.riskenginesdk.demo.ui.SpringTouchHelper;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.FingerprintId;
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

    private enum DetectionFilter {
        ALL, RISK, INFO, INCOMPLETE, NORMAL
    }

    private static final Object STATE_LOCK = new Object();
    private static WeakReference<MainActivity> activeActivity = new WeakReference<>(null);
    private static RiskReport latestReport;
    private static Throwable latestError;
    private static boolean collectionInFlight;
    private static long collectionStartedAtMs;
    private static long latestElapsedMs;
    private static long activeRequestToken;
    private static int savedSegmentIndex = 0;

    private ReportFormatter formatter;
    private FluidDetailSheet detailSheet;

    private View mainContentContainer;
    private View topBarContainer;
    private View bottomDockWrapper;
    private ScrollView scrollReport;
    private LinearLayout reportContent;

    // Idle / Scanning / Error stage
    private View stateStage;
    private RiskGaugeView stageGauge;
    private TextView tvStageTitle;
    private TextView tvStageSubtitle;
    private MaterialButton btnStartScan;
    private TextView tvPrivacyNote;

    // Top bar
    private TextView tvStickyVerdict;
    private ImageButton btnThemeToggle;

    // Hero & metrics
    private View cardHero;
    private RiskGaugeView heroGauge;
    private TextView tvHeroVerdict;
    private TextView tvHeroSummary;
    private TextView tvHeroMeta;
    private TextView tvMetricAttention;
    private TextView tvMetricCoverage;
    private TextView tvMetricFields;

    // Inconsistency banner
    private LinearLayout cardInconsistentBanner;
    private TextView tvInconsistentBannerSub;

    // Segmented control & panels
    private SegmentedControlView segmentedControl;
    private View panelDetections;
    private LinearLayout layoutFilterChips;
    private LinearLayout layoutDetections;
    private TextView tvCoverageGapsFooter;

    private View panelFingerprint;
    private View cardIdentity;
    private TextView tvIdentityCoverage;
    private LinearLayout layoutIdentityRows;
    private TextView tvCollectedSectionLabel;
    private LinearLayout layoutCollected;
    private TextView tvSyntheticSectionLabel;
    private View cardSyntheticList;
    private LinearLayout layoutSynthetic;

    // Floating dock
    private MaterialButton btnDockRescan;
    private MaterialButton btnDockCopy;

    // Detail sheet views
    private TextView tvSheetBadge;
    private TextView tvSheetTitle;
    private LinearLayout sheetBody;
    private ScrollView sheetScrollView;

    // Floating HUD capsule
    private View hudCapsule;
    private TextView tvHudMessage;
    private SpringAnimation hudSpringY;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final Runnable hideHudRunnable = this::hideHud;

    private DetectionFilter activeFilter = DetectionFilter.ALL;
    private List<DetectionResult> cachedDetections = new ArrayList<>();
    private boolean stickyVerdictVisible = false;
    private boolean reportHasRendered = false;
    private int statusBarInsetPx = 0;
    private int navBarInsetPx = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);
        setContentView(R.layout.activity_main);
        syncSystemBarAppearance();
        getWindow().getDecorView().post(this::syncSystemBarAppearance);

        formatter = new ReportFormatter(this);
        initViews();
        applyWindowInsets();
        initSdk();

        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                if (detailSheet != null && detailSheet.isShowing()) {
                    detailSheet.dismiss();
                } else {
                    setEnabled(false);
                    getOnBackPressedDispatcher().onBackPressed();
                }
            }
        });
    }

    @Override
    protected void onStart() {
        super.onStart();
        synchronized (STATE_LOCK) {
            activeActivity = new WeakReference<>(this);
        }
        renderSharedState(false);
    }

    @Override
    protected void onStop() {
        synchronized (STATE_LOCK) {
            if (activeActivity.get() == this) {
                activeActivity.clear();
            }
        }
        mainHandler.removeCallbacks(hideHudRunnable);
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
                savedSegmentIndex = 0;
            }
            RiskEngine.shutdown();
        }
        super.onDestroy();
    }

    private void initViews() {
        mainContentContainer = findViewById(R.id.mainContentContainer);
        topBarContainer = findViewById(R.id.topBarContainer);
        bottomDockWrapper = findViewById(R.id.bottomDockWrapper);
        scrollReport = findViewById(R.id.scrollReport);
        reportContent = findViewById(R.id.reportContent);

        stateStage = findViewById(R.id.stateStage);
        stageGauge = findViewById(R.id.stageGauge);
        tvStageTitle = findViewById(R.id.tvStageTitle);
        tvStageSubtitle = findViewById(R.id.tvStageSubtitle);
        btnStartScan = findViewById(R.id.btnStartScan);
        tvPrivacyNote = findViewById(R.id.tvPrivacyNote);

        tvStickyVerdict = findViewById(R.id.tvStickyVerdict);
        btnThemeToggle = findViewById(R.id.btnThemeToggle);

        cardHero = findViewById(R.id.cardHero);
        heroGauge = findViewById(R.id.heroGauge);
        tvHeroVerdict = findViewById(R.id.tvHeroVerdict);
        tvHeroSummary = findViewById(R.id.tvHeroSummary);
        tvHeroMeta = findViewById(R.id.tvHeroMeta);
        tvMetricAttention = findViewById(R.id.tvMetricAttention);
        tvMetricCoverage = findViewById(R.id.tvMetricCoverage);
        tvMetricFields = findViewById(R.id.tvMetricFields);

        cardInconsistentBanner = findViewById(R.id.cardInconsistentBanner);
        tvInconsistentBannerSub = findViewById(R.id.tvInconsistentBannerSub);
        styleInconsistentBanner();

        segmentedControl = findViewById(R.id.segmentedControl);
        panelDetections = findViewById(R.id.panelDetections);
        layoutFilterChips = findViewById(R.id.layoutFilterChips);
        layoutDetections = findViewById(R.id.layoutDetections);
        tvCoverageGapsFooter = findViewById(R.id.tvCoverageGapsFooter);

        panelFingerprint = findViewById(R.id.panelFingerprint);
        cardIdentity = findViewById(R.id.cardIdentity);
        tvIdentityCoverage = findViewById(R.id.tvIdentityCoverage);
        layoutIdentityRows = findViewById(R.id.layoutIdentityRows);
        tvCollectedSectionLabel = findViewById(R.id.tvCollectedSectionLabel);
        layoutCollected = findViewById(R.id.layoutCollected);
        tvSyntheticSectionLabel = findViewById(R.id.tvSyntheticSectionLabel);
        cardSyntheticList = findViewById(R.id.cardSyntheticList);
        layoutSynthetic = findViewById(R.id.layoutSynthetic);

        findViewById(R.id.cardDetectionsList).setClipToOutline(true);
        findViewById(R.id.cardCollectedList).setClipToOutline(true);
        cardSyntheticList.setClipToOutline(true);

        btnDockRescan = findViewById(R.id.btnDockRescan);
        btnDockCopy = findViewById(R.id.btnDockCopy);

        // Detail Sheet
        View sheetOverlay = findViewById(R.id.sheetOverlay);
        View sheetScrim = findViewById(R.id.sheetScrim);
        View sheetContainer = findViewById(R.id.sheetContainer);
        View sheetDragHeader = findViewById(R.id.sheetDragHeader);
        sheetScrollView = findViewById(R.id.sheetScrollView);
        tvSheetBadge = findViewById(R.id.tvSheetBadge);
        tvSheetTitle = findViewById(R.id.tvSheetTitle);
        sheetBody = findViewById(R.id.sheetBody);
        ImageButton btnSheetClose = findViewById(R.id.btnSheetClose);

        detailSheet = new FluidDetailSheet(
                sheetOverlay, sheetScrim, sheetContainer,
                sheetDragHeader, sheetScrollView, mainContentContainer);

        // HUD Capsule
        hudCapsule = findViewById(R.id.hudCapsule);
        tvHudMessage = findViewById(R.id.tvHudMessage);
        hudSpringY = new SpringAnimation(hudCapsule, DynamicAnimation.TRANSLATION_Y, 0f);
        SpringForce hudForce = new SpringForce(0f);
        hudForce.setDampingRatio(0.85f);
        hudForce.setStiffness(480f);
        hudSpringY.setSpring(hudForce);

        // Tactile spring press-down (Apple Design §1)
        SpringTouchHelper.attach(btnStartScan, 0.96f, true);
        SpringTouchHelper.attach(stageGauge, 0.94f, true);
        SpringTouchHelper.attach(btnDockRescan, 0.95f, true);
        SpringTouchHelper.attach(btnDockCopy, 0.95f, true);
        SpringTouchHelper.attachCompact(btnThemeToggle);
        SpringTouchHelper.attachCompact(btnSheetClose);
        SpringTouchHelper.attach(cardInconsistentBanner, 0.98f, true);

        stageGauge.setMode(RiskGaugeView.MODE_EMBLEM);
        stageGauge.setOnClickListener(v -> startCollection());
        btnStartScan.setOnClickListener(v -> startCollection());
        btnDockRescan.setOnClickListener(v -> startCollection());
        btnDockCopy.setOnClickListener(v -> copyRedactedReport());
        btnSheetClose.setOnClickListener(v -> detailSheet.dismiss());
        btnThemeToggle.setOnClickListener(v -> toggleTheme());

        segmentedControl.setSelectedIndex(savedSegmentIndex, false, false);
        segmentedControl.setOnSegmentSelectedListener(index -> {
            int previous = savedSegmentIndex;
            savedSegmentIndex = index;
            switchSegmentPanel(index, previous, true);
        });

        scrollReport.getViewTreeObserver().addOnScrollChangedListener(this::updateStickyVerdict);
    }

    private void applyWindowInsets() {
        View root = findViewById(R.id.rootContainer);
        ViewCompat.setOnApplyWindowInsetsListener(root, (v, windowInsets) -> {
            Insets bars = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars());
            statusBarInsetPx = bars.top;
            navBarInsetPx = bars.bottom;

            topBarContainer.setPadding(0, statusBarInsetPx, 0, dp(10));
            reportContent.setPadding(
                    dp(20),
                    statusBarInsetPx + dp(68),
                    dp(20),
                    navBarInsetPx + dp(112)
            );
            bottomDockWrapper.setPadding(
                    dp(20),
                    dp(20),
                    dp(20),
                    navBarInsetPx + dp(14)
            );
            sheetBody.setPadding(
                    dp(22),
                    dp(18),
                    dp(22),
                    navBarInsetPx + dp(28)
            );

            FrameLayout.LayoutParams hudLp = (FrameLayout.LayoutParams) hudCapsule.getLayoutParams();
            hudLp.topMargin = statusBarInsetPx + dp(10);
            hudCapsule.setLayoutParams(hudLp);

            // Cap sheet scroll viewport to ~62% of screen height so drag header stays reachable
            DisplayMetrics dm = getResources().getDisplayMetrics();
            int maxScrollH = Math.round(dm.heightPixels * 0.62f);
            sheetScrollView.addOnLayoutChangeListener((sv, l, t, r, b, ol, ot, or, ob) -> {
                View child = sheetScrollView.getChildAt(0);
                if (child != null) {
                    int desired = Math.min(child.getHeight(), maxScrollH);
                    ViewGroup.LayoutParams lp = sheetScrollView.getLayoutParams();
                    if (lp.height != desired && desired > 0) {
                        lp.height = desired;
                        sheetScrollView.setLayoutParams(lp);
                    }
                }
            });

            return windowInsets;
        });
    }

    private void initSdk() {
        RiskEngineConfig config = new RiskEngineConfig.Builder()
                .debugLog(BuildConfig.DEBUG)
                .collectTimeout(15_000)
                .build();
        RiskEngine.initIfNeeded(this, config);
    }

    private void syncSystemBarAppearance() {
        boolean isNight = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES;
        WindowInsetsControllerCompat controller =
                WindowCompat.getInsetsController(getWindow(), getWindow().getDecorView());
        controller.setAppearanceLightStatusBars(!isNight);
        controller.setAppearanceLightNavigationBars(!isNight);
    }

    private void toggleTheme() {
        int currentNight = getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
        int nextMode = currentNight == Configuration.UI_MODE_NIGHT_YES
                ? AppCompatDelegate.MODE_NIGHT_NO
                : AppCompatDelegate.MODE_NIGHT_YES;
        AppCompatDelegate.setDefaultNightMode(nextMode);
    }

    private void startCollection() {
        final long requestToken;
        synchronized (STATE_LOCK) {
            if (collectionInFlight) {
                showHud(getString(R.string.collecting_toast));
                return;
            }
            collectionInFlight = true;
            collectionStartedAtMs = System.currentTimeMillis();
            latestReport = null;
            latestError = null;
            requestToken = ++activeRequestToken;
        }

        if (detailSheet != null && detailSheet.isShowing()) {
            detailSheet.dismiss();
        }
        activeFilter = DetectionFilter.ALL;
        reportHasRendered = false;
        showScanningState();
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
                    latestElapsedMs = Math.max(0, System.currentTimeMillis() - collectionStartedAtMs);
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
                activity.renderSharedState(true);
                View hapticHost = activity.scrollReport.getVisibility() == View.VISIBLE
                        ? activity.cardHero
                        : activity.btnStartScan;
                hapticHost.performHapticFeedback(success
                        ? HapticFeedbackConstants.CONFIRM
                        : HapticFeedbackConstants.REJECT);
            });
        }
    }

    private void renderSharedState(boolean animateTransition) {
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
            showScanningState();
        } else if (report != null) {
            displayReport(report, elapsedMs, animateTransition || !reportHasRendered);
        } else if (error != null) {
            showErrorState(error);
        } else {
            showIdleState();
        }
    }

    private void showIdleState() {
        stageGauge.setMode(RiskGaugeView.MODE_EMBLEM);
        stageGauge.setScanning(false);
        stageGauge.setEnabled(true);

        tvStageTitle.setText(R.string.idle_title);
        tvStageTitle.setTextColor(color(R.color.text_primary));
        tvStageSubtitle.setText(R.string.idle_subtitle);
        btnStartScan.setText(R.string.collect_action);
        btnStartScan.setEnabled(true);
        btnStartScan.setAlpha(1f);
        btnStartScan.setVisibility(View.VISIBLE);
        tvPrivacyNote.setVisibility(View.VISIBLE);

        stateStage.setVisibility(View.VISIBLE);
        stateStage.setAlpha(1f);
        scrollReport.setVisibility(View.GONE);
        bottomDockWrapper.setVisibility(View.GONE);
        hideStickyVerdictImmediate();
    }

    private void showScanningState() {
        stageGauge.setMode(RiskGaugeView.MODE_EMBLEM);
        stageGauge.setScanning(true);
        stageGauge.setEnabled(false);

        tvStageTitle.setText(R.string.collecting_title);
        tvStageTitle.setTextColor(color(R.color.text_primary));
        tvStageSubtitle.setText(R.string.collecting_subtitle);
        btnStartScan.setText(R.string.collecting_action);
        btnStartScan.setEnabled(false);
        btnStartScan.setAlpha(0.55f);
        btnStartScan.setVisibility(View.VISIBLE);
        tvPrivacyNote.setVisibility(View.GONE);

        stateStage.setVisibility(View.VISIBLE);
        stateStage.setAlpha(1f);
        scrollReport.setVisibility(View.GONE);
        bottomDockWrapper.setVisibility(View.GONE);
        hideStickyVerdictImmediate();
    }

    private void showErrorState(Throwable error) {
        stageGauge.setMode(RiskGaugeView.MODE_EMBLEM);
        stageGauge.setScanning(false);
        stageGauge.setEnabled(true);

        tvStageTitle.setText(R.string.collection_failed);
        tvStageTitle.setTextColor(color(R.color.risk_deadly));
        String msg = error.getMessage();
        if (msg == null || msg.isBlank()) {
            msg = getString(R.string.unknown_error);
        }
        tvStageSubtitle.setText(getString(R.string.collection_failed_description, msg));
        btnStartScan.setText(R.string.retry_action);
        btnStartScan.setEnabled(true);
        btnStartScan.setAlpha(1f);
        btnStartScan.setVisibility(View.VISIBLE);
        tvPrivacyNote.setVisibility(View.GONE);

        stateStage.setVisibility(View.VISIBLE);
        scrollReport.setVisibility(View.GONE);
        bottomDockWrapper.setVisibility(View.GONE);
        hideStickyVerdictImmediate();
    }

    private void displayReport(RiskReport report, long elapsedMs, boolean animate) {
        reportHasRendered = true;
        stageGauge.setScanning(false);
        stateStage.setVisibility(View.GONE);
        scrollReport.setVisibility(View.VISIBLE);
        bottomDockWrapper.setVisibility(View.VISIBLE);

        RiskLevel level = report.getOverallRiskLevel();
        @ColorInt int levelColor = color(formatter.riskColorRes(level));
        @ColorInt int levelBg = color(formatter.riskBgRes(level));
        String levelLabel = formatter.riskLabel(level);

        // Hero gauge & verdict (zero redundancy!)
        heroGauge.setScore(report.getRiskScore(), report.getDisplayThresholdMaximum(), levelColor, animate);
        heroGauge.setContentDescription(getString(R.string.risk_progress_value,
                report.getRiskScore(), report.getDisplayThresholdMaximum()));

        tvHeroVerdict.setText(levelLabel);
        tvHeroVerdict.setTextColor(levelColor);
        tvHeroSummary.setText(formatter.heroSubtitle(report));

        String time = DateFormat.getTimeInstance(DateFormat.MEDIUM, Locale.getDefault())
                .format(new Date(report.getTimestampMs()));
        tvHeroMeta.setText(getString(R.string.hero_meta, time, formatter.formatElapsed(elapsedMs)));

        // Sticky verdict pill in top bar (shown dynamically on scroll)
        tvStickyVerdict.setText(levelLabel);
        tvStickyVerdict.setTextColor(levelColor);
        tvStickyVerdict.setBackground(createPillDrawable(levelBg));

        // 3-Column Clean Inline Metrics
        cachedDetections = formatter.environmentDetections(report);
        int attentionCount = formatter.countActionableAttention(cachedDetections);
        tvMetricAttention.setText(String.valueOf(attentionCount));
        tvMetricAttention.setTextColor(attentionCount > 0 ? levelColor : color(R.color.text_primary));
        tvMetricCoverage.setText(getString(R.string.coverage_percent, report.getCoveragePercent()));

        Map<String, CollectorResult> fpResults = report.getFingerprint().getResults();
        int collectedCount = 0;
        for (CollectorResult r : fpResults.values()) {
            if (!formatter.isSyntheticCollector(r.getFieldName())) {
                collectedCount++;
            }
        }
        tvMetricFields.setText(String.valueOf(collectedCount));

        // Multi-source inconsistency banner
        List<String> inconsistent = report.getFingerprint().getInconsistentFields();
        if (inconsistent.isEmpty()) {
            cardInconsistentBanner.setVisibility(View.GONE);
        } else {
            cardInconsistentBanner.setVisibility(View.VISIBLE);
            tvInconsistentBannerSub.setText(
                    getString(R.string.inconsistent_banner_subtitle, inconsistent.size()));
            cardInconsistentBanner.setOnClickListener(v -> openInconsistentSheet(report, inconsistent));
        }

        // Segmented Control labels with live counts
        segmentedControl.setLabels(
                getString(R.string.segment_detections_count, cachedDetections.size()),
                getString(R.string.segment_fingerprint_count, fpResults.size())
        );
        segmentedControl.setSelectedIndex(savedSegmentIndex, false, false);
        switchSegmentPanel(savedSegmentIndex, savedSegmentIndex, false);

        // Render Tabs
        renderFilterChips();
        renderDetectionsList(report);
        renderFingerprintTab(report);

        if (animate && animationsEnabled()) {
            scrollReport.scrollTo(0, 0);
            hideStickyVerdictImmediate();
            animateReportEntrance();
        } else {
            reportContent.setAlpha(1f);
            reportContent.setTranslationY(0f);
            bottomDockWrapper.setAlpha(1f);
            bottomDockWrapper.setTranslationY(0f);
            updateStickyVerdict();
        }
    }

    private void animateReportEntrance() {
        reportContent.setAlpha(0f);
        reportContent.setTranslationY(dp(18));
        reportContent.animate()
                .alpha(1f)
                .setDuration(260)
                .start();

        SpringAnimation contentSpring = new SpringAnimation(reportContent, DynamicAnimation.TRANSLATION_Y, 0f);
        SpringForce f = new SpringForce(0f);
        f.setDampingRatio(1.0f);
        f.setStiffness(340f);
        contentSpring.setSpring(f);
        contentSpring.start();

        bottomDockWrapper.setAlpha(0f);
        bottomDockWrapper.setTranslationY(dp(26));
        bottomDockWrapper.animate().alpha(1f).setDuration(240).start();

        SpringAnimation dockSpring = new SpringAnimation(bottomDockWrapper, DynamicAnimation.TRANSLATION_Y, 0f);
        SpringForce df = new SpringForce(0f);
        df.setDampingRatio(0.86f);
        df.setStiffness(380f);
        dockSpring.setSpring(df);
        dockSpring.start();
    }

    private void switchSegmentPanel(int newIndex, int oldIndex, boolean animate) {
        View incoming = newIndex == 0 ? panelDetections : panelFingerprint;
        View outgoing = newIndex == 0 ? panelFingerprint : panelDetections;

        outgoing.animate().cancel();
        incoming.animate().cancel();
        outgoing.setVisibility(View.GONE);
        incoming.setVisibility(View.VISIBLE);

        if (!animate || !animationsEnabled() || newIndex == oldIndex) {
            incoming.setAlpha(1f);
            incoming.setTranslationX(0f);
            return;
        }

        // Apple Design §7: Spatial consistency — slide subtly from the segment's direction
        float direction = newIndex > oldIndex ? 1f : -1f;
        incoming.setAlpha(0f);
        incoming.setTranslationX(direction * dp(18));
        incoming.animate().alpha(1f).setDuration(200).start();

        SpringAnimation slideSpring = new SpringAnimation(incoming, DynamicAnimation.TRANSLATION_X, 0f);
        SpringForce force = new SpringForce(0f);
        force.setDampingRatio(1.0f);
        force.setStiffness(460f);
        slideSpring.setSpring(force);
        slideSpring.start();
    }

    private void renderFilterChips() {
        layoutFilterChips.removeAllViews();

        int allCount = cachedDetections.size();
        int riskCount = 0;
        int infoCount = 0;
        int incompleteCount = 0;
        int normalCount = 0;
        for (DetectionResult d : cachedDetections) {
            if (formatter.isActionableRisk(d)) riskCount++;
            else if (formatter.isInformationalItem(d)) infoCount++;
            else if (formatter.isIncompleteItem(d)) incompleteCount++;
            else normalCount++;
        }

        // Reset filter if selected bucket is empty
        if ((activeFilter == DetectionFilter.RISK && riskCount == 0)
                || (activeFilter == DetectionFilter.INFO && infoCount == 0)
                || (activeFilter == DetectionFilter.INCOMPLETE && incompleteCount == 0)
                || (activeFilter == DetectionFilter.NORMAL && normalCount == 0)) {
            activeFilter = DetectionFilter.ALL;
        }

        addFilterChip(DetectionFilter.ALL, getString(R.string.filter_all, allCount));
        if (riskCount > 0) addFilterChip(DetectionFilter.RISK, getString(R.string.filter_risk, riskCount));
        if (infoCount > 0) addFilterChip(DetectionFilter.INFO, getString(R.string.filter_info, infoCount));
        if (incompleteCount > 0) {
            addFilterChip(DetectionFilter.INCOMPLETE, getString(R.string.filter_incomplete, incompleteCount));
        }
        if (normalCount > 0) addFilterChip(DetectionFilter.NORMAL, getString(R.string.filter_normal, normalCount));
    }

    private void addFilterChip(DetectionFilter filter, String label) {
        boolean selected = activeFilter == filter;
        TextView chip = new TextView(this);
        chip.setText(label);
        chip.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.5f);
        chip.setTypeface(Typeface.create("sans-serif-medium", selected ? Typeface.BOLD : Typeface.NORMAL));
        chip.setTextColor(color(selected ? R.color.action_primary_fg : R.color.text_secondary));
        chip.setPadding(dp(14), dp(7), dp(14), dp(7));
        chip.setFontFeatureSettings("tnum");

        GradientDrawable bg = new GradientDrawable();
        bg.setShape(GradientDrawable.RECTANGLE);
        bg.setCornerRadius(dp(999));
        bg.setColor(color(selected ? R.color.action_primary_bg : R.color.surface));
        if (!selected) {
            bg.setStroke(dp(1), color(R.color.stroke_subtle));
        }
        chip.setBackground(bg);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMarginEnd(dp(8));
        chip.setLayoutParams(lp);
        chip.setClickable(true);
        chip.setFocusable(true);
        SpringTouchHelper.attachCompact(chip);
        chip.setOnClickListener(v -> {
            if (activeFilter != filter) {
                activeFilter = filter;
                renderFilterChips();
                synchronized (STATE_LOCK) {
                    if (latestReport != null) {
                        renderDetectionsList(latestReport);
                    }
                }
            }
        });
        layoutFilterChips.addView(chip);
    }

    private void renderDetectionsList(RiskReport report) {
        layoutDetections.removeAllViews();

        List<DetectionResult> filtered = new ArrayList<>();
        for (DetectionResult d : cachedDetections) {
            if (matchesFilter(d, activeFilter)) {
                filtered.add(d);
            }
        }

        if (filtered.isEmpty()) {
            TextView empty = createText(getString(R.string.filter_empty_state), 13.5f, R.color.text_tertiary, Typeface.NORMAL);
            empty.setGravity(Gravity.CENTER);
            empty.setPadding(dp(20), dp(28), dp(20), dp(28));
            layoutDetections.addView(empty);
        } else {
            for (int i = 0; i < filtered.size(); i++) {
                layoutDetections.addView(createDetectionRow(filtered.get(i)));
                if (i < filtered.size() - 1) {
                    layoutDetections.addView(createInsetHairline(dp(36)));
                }
            }
        }

        int gaps = formatter.countCollectorCoverageGaps(report);
        if (gaps > 0) {
            tvCoverageGapsFooter.setVisibility(View.VISIBLE);
            tvCoverageGapsFooter.setText(getString(R.string.coverage_gaps_footer, gaps));
        } else {
            tvCoverageGapsFooter.setVisibility(View.GONE);
        }
    }

    private boolean matchesFilter(DetectionResult d, DetectionFilter filter) {
        switch (filter) {
            case RISK: return formatter.isActionableRisk(d);
            case INFO: return formatter.isInformationalItem(d);
            case INCOMPLETE: return formatter.isIncompleteItem(d);
            case NORMAL: return formatter.isCleanNormal(d);
            case ALL:
            default: return true;
        }
    }

    private View createDetectionRow(DetectionResult detection) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(16), dp(14), dp(14), dp(14));
        row.setMinimumHeight(dp(60));
        row.setClickable(true);
        row.setFocusable(true);
        applyRowRipple(row);

        @ColorInt int statusColor = color(formatter.detectionStatusColorRes(detection));
        @ColorInt int statusBg = color(formatter.detectionStatusBgRes(detection));

        // Status dot
        View dot = new View(this);
        LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dp(8), dp(8));
        dotLp.setMarginEnd(dp(12));
        dot.setLayoutParams(dotLp);
        dot.setBackground(createCircleDrawable(statusColor));
        row.addView(dot);

        // Title + concise 1-line summary
        LinearLayout textCol = new LinearLayout(this);
        textCol.setOrientation(LinearLayout.VERTICAL);
        textCol.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView title = createText(formatter.detectorTitle(detection.getDetectorName()),
                15f, R.color.text_primary, Typeface.BOLD);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        textCol.addView(title);

        TextView summary = createText(formatter.detectionSummary(detection),
                12.5f, R.color.text_secondary, Typeface.NORMAL);
        summary.setMaxLines(1);
        summary.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams sumLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sumLp.topMargin = dp(3);
        summary.setLayoutParams(sumLp);
        textCol.addView(summary);
        row.addView(textCol);

        // Right trailing status: quiet checkmark for clean NORMAL, crisp pill for notable statuses
        if (formatter.isCleanNormal(detection)) {
            ImageView check = new ImageView(this);
            LinearLayout.LayoutParams checkLp = new LinearLayout.LayoutParams(dp(16), dp(16));
            checkLp.setMarginStart(dp(10));
            check.setLayoutParams(checkLp);
            check.setImageResource(R.drawable.ic_check_subtle);
            row.addView(check);
        } else {
            TextView pill = createPill(formatter.detectionStatusLabel(detection), statusColor, statusBg);
            LinearLayout.LayoutParams pillLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            pillLp.setMarginStart(dp(10));
            pill.setLayoutParams(pillLp);
            row.addView(pill);
        }

        ImageView chevron = new ImageView(this);
        LinearLayout.LayoutParams chevLp = new LinearLayout.LayoutParams(dp(14), dp(14));
        chevLp.setMarginStart(dp(6));
        chevron.setLayoutParams(chevLp);
        chevron.setImageResource(R.drawable.ic_chevron_right);
        row.addView(chevron);

        row.setContentDescription(getString(R.string.row_content_description,
                formatter.detectorTitle(detection.getDetectorName()),
                formatter.detectionStatusLabel(detection)));
        row.setOnClickListener(v -> openDetectionSheet(detection));
        return row;
    }

    private void renderFingerprintTab(RiskReport report) {
        // 1. Layered Device Fingerprint Identity Card
        FingerprintId fpId = report.getFingerprintId();
        layoutIdentityRows.removeAllViews();
        if (fpId != null && (!fpId.getCompositeId().isEmpty() || !fpId.getHardwareId().isEmpty())) {
            cardIdentity.setVisibility(View.VISIBLE);
            tvIdentityCoverage.setText(getString(R.string.identity_hardware_coverage,
                    fpId.getHardwareCoveragePercent(),
                    fpId.getHardwareFieldsPresent(),
                    fpId.getHardwareFieldsTotal()));

            List<String[]> layers = new ArrayList<>();
            if (!fpId.getCompositeId().isEmpty()) {
                layers.add(new String[]{getString(R.string.identity_composite), fpId.getCompositeId()});
            }
            if (!fpId.getHardwareId().isEmpty()) {
                layers.add(new String[]{getString(R.string.identity_hardware), fpId.getHardwareId()});
            }
            if (!fpId.getSystemId().isEmpty()) {
                layers.add(new String[]{getString(R.string.identity_system), fpId.getSystemId()});
            }
            if (!fpId.getVolatileId().isEmpty()) {
                layers.add(new String[]{getString(R.string.identity_volatile), fpId.getVolatileId()});
            }

            for (int i = 0; i < layers.size(); i++) {
                layoutIdentityRows.addView(createIdentityLayerRow(layers.get(i)[0], layers.get(i)[1]));
                if (i < layers.size() - 1) {
                    layoutIdentityRows.addView(createInsetHairline(0));
                }
            }
        } else {
            cardIdentity.setVisibility(View.GONE);
        }

        // 2. Collected Attributes & Synthetic Analysis
        layoutCollected.removeAllViews();
        layoutSynthetic.removeAllViews();

        List<CollectorResult> collected = new ArrayList<>();
        List<CollectorResult> synthetic = new ArrayList<>();
        for (CollectorResult r : report.getFingerprint().getResults().values()) {
            if (formatter.isSyntheticCollector(r.getFieldName())) {
                synthetic.add(r);
            } else {
                collected.add(r);
            }
        }

        tvCollectedSectionLabel.setText(getString(R.string.fingerprint_section_collected, collected.size()));
        for (int i = 0; i < collected.size(); i++) {
            layoutCollected.addView(createCollectorRow(collected.get(i)));
            if (i < collected.size() - 1) {
                layoutCollected.addView(createInsetHairline(dp(16)));
            }
        }

        if (synthetic.isEmpty()) {
            tvSyntheticSectionLabel.setVisibility(View.GONE);
            cardSyntheticList.setVisibility(View.GONE);
        } else {
            tvSyntheticSectionLabel.setVisibility(View.VISIBLE);
            cardSyntheticList.setVisibility(View.VISIBLE);
            tvSyntheticSectionLabel.setText(getString(R.string.fingerprint_section_synthetic, synthetic.size()));
            for (int i = 0; i < synthetic.size(); i++) {
                layoutSynthetic.addView(createCollectorRow(synthetic.get(i)));
                if (i < synthetic.size() - 1) {
                    layoutSynthetic.addView(createInsetHairline(dp(16)));
                }
            }
        }
    }

    private View createIdentityLayerRow(String label, String fullHash) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(10), 0, dp(10));

        TextView tvLabel = createText(label, 13f, R.color.text_secondary, Typeface.NORMAL);
        tvLabel.setLayoutParams(new LinearLayout.LayoutParams(dp(72), ViewGroup.LayoutParams.WRAP_CONTENT));
        row.addView(tvLabel);

        TextView tvHash = createText(formatter.shortenHash(fullHash), 12.5f, R.color.text_primary, Typeface.NORMAL);
        tvHash.setTypeface(Typeface.MONOSPACE);
        tvHash.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(tvHash);

        TextView btnCopy = createPill(getString(R.string.copy_value_short),
                color(R.color.accent), color(R.color.accent_soft));
        btnCopy.setClickable(true);
        btnCopy.setFocusable(true);
        SpringTouchHelper.attachCompact(btnCopy);
        btnCopy.setOnClickListener(v -> copyPlainText(label, fullHash, getString(R.string.copy_value_success)));
        row.addView(btnCopy);
        return row;
    }

    private View createCollectorRow(CollectorResult result) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(16), dp(13), dp(14), dp(13));
        row.setMinimumHeight(dp(58));
        row.setClickable(true);
        row.setFocusable(true);
        applyRowRipple(row);

        LinearLayout textCol = new LinearLayout(this);
        textCol.setOrientation(LinearLayout.VERTICAL);
        textCol.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        TextView title = createText(formatter.collectorTitle(result.getFieldName()),
                14.5f, R.color.text_primary, Typeface.BOLD);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        textCol.addView(title);

        TextView summary = createText(formatter.collectorSummary(result),
                12.5f, R.color.text_secondary, Typeface.NORMAL);
        summary.setMaxLines(2);
        summary.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams sumLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        sumLp.topMargin = dp(3);
        summary.setLayoutParams(sumLp);
        textCol.addView(summary);
        row.addView(textCol);

        // Only show status badge for non-SUCCESS states (removes repetitive green badge noise!)
        if (result.getStatus() != CollectorResult.Status.SUCCESS) {
            TextView pill = createPill(
                    formatter.collectorStatusLabel(result.getStatus()),
                    color(formatter.collectorStatusColorRes(result.getStatus())),
                    color(formatter.collectorStatusBgRes(result.getStatus()))
            );
            LinearLayout.LayoutParams pillLp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            pillLp.setMarginStart(dp(10));
            pill.setLayoutParams(pillLp);
            row.addView(pill);
        }

        ImageView chevron = new ImageView(this);
        LinearLayout.LayoutParams chevLp = new LinearLayout.LayoutParams(dp(14), dp(14));
        chevLp.setMarginStart(dp(8));
        chevron.setLayoutParams(chevLp);
        chevron.setImageResource(R.drawable.ic_chevron_right);
        row.addView(chevron);

        row.setContentDescription(getString(R.string.row_content_description,
                formatter.collectorTitle(result.getFieldName()),
                formatter.collectorStatusLabel(result.getStatus())));
        row.setOnClickListener(v -> openCollectorSheet(result));
        return row;
    }

    // ---- Detail Sheet Presenters ----

    private void openDetectionSheet(DetectionResult detection) {
        @ColorInt int statusColor = color(formatter.detectionStatusColorRes(detection));
        @ColorInt int statusBg = color(formatter.detectionStatusBgRes(detection));

        tvSheetBadge.setText(formatter.detectionStatusLabel(detection));
        tvSheetBadge.setTextColor(statusColor);
        tvSheetBadge.setBackground(createPillDrawable(statusBg));
        tvSheetTitle.setText(formatter.detectorTitle(detection.getDetectorName()));

        sheetBody.removeAllViews();

        // 1. Concise summary
        addSheetSectionTitle(getString(R.string.sheet_section_summary), false);
        TextView summary = createText(formatter.detectionSummary(detection), 14.5f, R.color.text_primary, Typeface.NORMAL);
        summary.setLineSpacing(dp(3), 1f);
        sheetBody.addView(summary);

        // 2. Metadata grid
        addSheetSectionTitle(getString(R.string.sheet_section_metrics), true);
        LinearLayout metaCard = createSheetWell();
        String scoreText = detection.isInformational()
                ? getString(R.string.sheet_score_informational)
                : getString(R.string.sheet_score_value, detection.getScore(), detection.getMaxScore());
        addSheetKeyValue(metaCard, getString(R.string.sheet_meta_execution), formatter.executionStatusLabel(detection), false);
        addSheetKeyValue(metaCard, getString(R.string.sheet_meta_score), scoreText, false);
        addSheetKeyValue(metaCard, getString(R.string.sheet_meta_coverage),
                getString(R.string.sheet_coverage_value, detection.getChecksSucceeded(), detection.getChecksAttempted()), false);
        addSheetKeyValue(metaCard, getString(R.string.sheet_meta_detector_id), detection.getDetectorName(), true);
        sheetBody.addView(metaCard);

        // 3. Evidence bullets
        addSheetSectionTitle(getString(R.string.sheet_section_evidence), true);
        List<String> bullets = formatter.detectionEvidenceBullets(detection);
        if (bullets.isEmpty()) {
            TextView none = createText(getString(R.string.sheet_no_evidence), 13.5f, R.color.text_secondary, Typeface.NORMAL);
            sheetBody.addView(none);
        } else {
            for (String item : bullets) {
                LinearLayout bulletRow = new LinearLayout(this);
                bulletRow.setOrientation(LinearLayout.HORIZONTAL);
                bulletRow.setPadding(0, dp(4), 0, dp(4));

                TextView bulletMark = createText("•", 14f, R.color.text_tertiary, Typeface.BOLD);
                bulletMark.setPadding(0, 0, dp(8), 0);
                bulletRow.addView(bulletMark);

                TextView bulletText = createText(item, 13.5f, R.color.text_primary, Typeface.NORMAL);
                bulletText.setLineSpacing(dp(2), 1f);
                bulletText.setTextIsSelectable(true);
                bulletRow.addView(bulletText);
                sheetBody.addView(bulletRow);
            }
        }

        // 4. Raw technical evidence block with one-tap Copy
        String raw = formatter.detectionRawDetails(detection);
        if (!raw.isBlank()) {
            addSheetSectionTitleWithCopy(getString(R.string.sheet_section_raw), raw);
            sheetBody.addView(createMonospaceCodeBlock(raw));
        }

        detailSheet.show();
    }

    private void openCollectorSheet(CollectorResult result) {
        @ColorInt int statusColor = color(formatter.collectorStatusColorRes(result.getStatus()));
        @ColorInt int statusBg = color(formatter.collectorStatusBgRes(result.getStatus()));

        tvSheetBadge.setText(formatter.collectorStatusLabel(result.getStatus()));
        tvSheetBadge.setTextColor(statusColor);
        tvSheetBadge.setBackground(createPillDrawable(statusBg));
        tvSheetTitle.setText(formatter.collectorTitle(result.getFieldName()));

        sheetBody.removeAllViews();

        // Metadata well
        LinearLayout metaCard = createSheetWell();
        addSheetKeyValue(metaCard, getString(R.string.sheet_meta_field_id), result.getFieldName(), true);
        addSheetKeyValue(metaCard, getString(R.string.sheet_meta_sensitivity),
                formatter.collectorSensitivityLabel(result.getFieldName()), false);
        addSheetKeyValue(metaCard, getString(R.string.sheet_meta_status),
                formatter.collectorStatusLabel(result.getStatus()), false);
        if (result.getCanonicalValue() != null && !result.getCanonicalValue().isBlank()) {
            addSheetKeyValue(metaCard, getString(R.string.sheet_meta_canonical),
                    formatter.formatCollectorValue(result.getFieldName(), "canonical", result.getCanonicalValue(), false),
                    true);
        }
        sheetBody.addView(metaCard);

        // Sources & values
        Map<String, String> entries = formatter.collectorFormattedEntries(result);
        StringBuilder copyBuf = new StringBuilder();
        for (Map.Entry<String, String> entry : entries.entrySet()) {
            if (copyBuf.length() > 0) copyBuf.append('\n');
            copyBuf.append(entry.getKey()).append(": ").append(entry.getValue());
        }

        if (!entries.isEmpty()) {
            addSheetSectionTitleWithCopy(getString(R.string.sheet_section_sources), copyBuf.toString());
            LinearLayout valWell = createSheetWell();
            int i = 0;
            for (Map.Entry<String, String> entry : entries.entrySet()) {
                TextView k = createText(entry.getKey(), 11.5f, R.color.text_tertiary, Typeface.BOLD);
                if (i > 0) {
                    LinearLayout.LayoutParams klp = new LinearLayout.LayoutParams(
                            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                    klp.topMargin = dp(10);
                    k.setLayoutParams(klp);
                }
                valWell.addView(k);

                TextView v = createText(entry.getValue(), 12.5f, R.color.text_primary, Typeface.NORMAL);
                v.setTypeface(Typeface.MONOSPACE);
                v.setTextIsSelectable(true);
                v.setLineSpacing(dp(2), 1f);
                LinearLayout.LayoutParams vlp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                vlp.topMargin = dp(3);
                v.setLayoutParams(vlp);
                valWell.addView(v);
                i++;
            }
            sheetBody.addView(valWell);
        } else if (result.getError() != null && !result.getError().isBlank()) {
            addSheetSectionTitle(getString(R.string.sheet_section_summary), true);
            sheetBody.addView(createText(formatter.humanizeFailureReason(result.getError()),
                    13.5f, R.color.text_secondary, Typeface.NORMAL));
        }

        detailSheet.show();
    }

    private void openInconsistentSheet(RiskReport report, List<String> inconsistent) {
        tvSheetBadge.setText(getString(R.string.inconsistent_title));
        tvSheetBadge.setTextColor(color(R.color.inconsistent_text));
        tvSheetBadge.setBackground(createPillDrawable(color(R.color.inconsistent_bg)));
        tvSheetTitle.setText(getString(R.string.inconsistent_title));

        sheetBody.removeAllViews();
        for (int i = 0; i < inconsistent.size(); i++) {
            String field = inconsistent.get(i);
            addSheetSectionTitle(formatter.collectorTitle(field) + " · " + field, i > 0);
            CollectorResult cr = report.getFingerprint().getResults().get(field);
            if (cr != null) {
                StringBuilder sb = new StringBuilder();
                for (Map.Entry<String, String> entry : formatter.collectorFormattedEntries(cr).entrySet()) {
                    if (sb.length() > 0) sb.append('\n');
                    sb.append(entry.getKey()).append("：").append(entry.getValue());
                }
                sheetBody.addView(createMonospaceCodeBlock(sb.toString()));
            }
        }
        detailSheet.show();
    }

    // ---- Scroll-Reactive Sticky Verdict Pill ----

    private void updateStickyVerdict() {
        if (scrollReport.getVisibility() != View.VISIBLE) {
            return;
        }
        boolean shouldShow = scrollReport.getScrollY() > dp(126);
        if (shouldShow == stickyVerdictVisible) {
            return;
        }
        stickyVerdictVisible = shouldShow;
        tvStickyVerdict.animate().cancel();
        if (shouldShow) {
            tvStickyVerdict.setVisibility(View.VISIBLE);
            if (animationsEnabled()) {
                tvStickyVerdict.animate().alpha(1f).scaleX(1f).scaleY(1f).setDuration(180).start();
            } else {
                tvStickyVerdict.setAlpha(1f);
                tvStickyVerdict.setScaleX(1f);
                tvStickyVerdict.setScaleY(1f);
            }
        } else {
            if (animationsEnabled()) {
                tvStickyVerdict.animate().alpha(0f).scaleX(0.92f).scaleY(0.92f).setDuration(140)
                        .withEndAction(() -> {
                            if (!stickyVerdictVisible) {
                                tvStickyVerdict.setVisibility(View.GONE);
                            }
                        }).start();
            } else {
                hideStickyVerdictImmediate();
            }
        }
    }

    private void hideStickyVerdictImmediate() {
        stickyVerdictVisible = false;
        tvStickyVerdict.animate().cancel();
        tvStickyVerdict.setVisibility(View.GONE);
        tvStickyVerdict.setAlpha(0f);
        tvStickyVerdict.setScaleX(0.92f);
        tvStickyVerdict.setScaleY(0.92f);
    }

    // ---- Clipboard & Floating Capsule HUD ----

    private void copyRedactedReport() {
        RiskReport report;
        synchronized (STATE_LOCK) {
            report = latestReport;
        }
        if (report == null) return;
        copyPlainText(
                getString(R.string.copy_redacted_report_label),
                formatter.buildRedactedSummary(report),
                getString(R.string.copy_redacted_report_success)
        );
    }

    private void copyPlainText(String label, String text, String hudConfirmation) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm == null) return;
        cm.setPrimaryClip(ClipData.newPlainText(label, text));
        rootHapticConfirm();
        showHud(hudConfirmation);
    }

    private void showHud(String message) {
        mainHandler.removeCallbacks(hideHudRunnable);
        tvHudMessage.setText(message);
        hudCapsule.setVisibility(View.VISIBLE);
        hudCapsule.animate().cancel();

        if (!animationsEnabled()) {
            hudCapsule.setTranslationY(0f);
            hudCapsule.setAlpha(1f);
        } else {
            hudCapsule.setAlpha(0f);
            hudCapsule.setTranslationY(-dp(44));
            hudCapsule.animate().alpha(1f).setDuration(160).start();
            hudSpringY.cancel();
            hudSpringY.animateToFinalPosition(0f);
        }
        mainHandler.postDelayed(hideHudRunnable, 1900L);
    }

    private void hideHud() {
        if (hudCapsule.getVisibility() != View.VISIBLE) return;
        if (!animationsEnabled()) {
            hudCapsule.setVisibility(View.GONE);
            return;
        }
        hudCapsule.animate()
                .alpha(0f)
                .translationY(-dp(28))
                .setDuration(180)
                .withEndAction(() -> hudCapsule.setVisibility(View.GONE))
                .start();
    }

    private void rootHapticConfirm() {
        View root = findViewById(R.id.rootContainer);
        if (root != null) {
            root.performHapticFeedback(HapticFeedbackConstants.CONFIRM);
        }
    }

    // ---- UI Building Helpers ----

    private void styleInconsistentBanner() {
        GradientDrawable bg = new GradientDrawable();
        bg.setShape(GradientDrawable.RECTANGLE);
        bg.setCornerRadius(dp(18));
        bg.setColor(color(R.color.inconsistent_bg));
        bg.setStroke(dp(1), color(R.color.inconsistent_stroke));
        cardInconsistentBanner.setBackground(bg);
    }

    private void addSheetSectionTitle(String title, boolean topMargin) {
        TextView tv = createText(title, 12.5f, R.color.text_secondary, Typeface.BOLD);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = topMargin ? dp(18) : 0;
        lp.bottomMargin = dp(8);
        tv.setLayoutParams(lp);
        sheetBody.addView(tv);
    }

    private void addSheetSectionTitleWithCopy(String title, String copyContent) {
        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(18);
        lp.bottomMargin = dp(8);
        header.setLayoutParams(lp);

        TextView tv = createText(title, 12.5f, R.color.text_secondary, Typeface.BOLD);
        tv.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        header.addView(tv);

        TextView btnCopy = createPill(getString(R.string.copy_value_short),
                color(R.color.accent), color(R.color.accent_soft));
        btnCopy.setClickable(true);
        btnCopy.setFocusable(true);
        SpringTouchHelper.attachCompact(btnCopy);
        btnCopy.setOnClickListener(v -> copyPlainText(title, copyContent, getString(R.string.copy_value_success)));
        header.addView(btnCopy);

        sheetBody.addView(header);
    }

    private LinearLayout createSheetWell() {
        LinearLayout well = new LinearLayout(this);
        well.setOrientation(LinearLayout.VERTICAL);
        well.setBackgroundResource(R.drawable.bg_code_block);
        well.setPadding(dp(14), dp(12), dp(14), dp(12));
        return well;
    }

    private void addSheetKeyValue(LinearLayout container, String key, String value, boolean mono) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(5), 0, dp(5));

        TextView tvKey = createText(key, 13f, R.color.text_secondary, Typeface.NORMAL);
        tvKey.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(tvKey);

        TextView tvVal = createText(value, mono ? 12f : 13f, R.color.text_primary, Typeface.BOLD);
        if (mono) {
            tvVal.setTypeface(Typeface.MONOSPACE);
            tvVal.setTextIsSelectable(true);
        } else {
            tvVal.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        }
        tvVal.setGravity(Gravity.END);
        tvVal.setFontFeatureSettings("tnum");
        row.addView(tvVal);
        container.addView(row);
    }

    private TextView createMonospaceCodeBlock(String code) {
        TextView tv = createText(code, 11.5f, R.color.text_secondary, Typeface.NORMAL);
        tv.setTypeface(Typeface.MONOSPACE);
        tv.setTextIsSelectable(true);
        tv.setLineSpacing(dp(3), 1f);
        tv.setBackgroundResource(R.drawable.bg_code_block);
        tv.setPadding(dp(14), dp(12), dp(14), dp(12));
        return tv;
    }

    private View createInsetHairline(int marginStartPx) {
        View line = new View(this);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1));
        lp.setMarginStart(marginStartPx);
        line.setLayoutParams(lp);
        line.setBackgroundColor(color(R.color.hairline));
        return line;
    }

    private TextView createPill(String text, @ColorInt int textColor, @ColorInt int bgColor) {
        TextView pill = new TextView(this);
        pill.setText(text);
        pill.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f);
        pill.setTextColor(textColor);
        pill.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        pill.setBackground(createPillDrawable(bgColor));
        pill.setPadding(dp(9), dp(4), dp(9), dp(4));
        return pill;
    }

    private TextView createText(String text, float sp, @ColorRes int colorRes, int style) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        tv.setTextColor(color(colorRes));
        tv.setTypeface(tv.getTypeface(), style);
        return tv;
    }

    private GradientDrawable createPillDrawable(@ColorInt int colorInt) {
        GradientDrawable d = new GradientDrawable();
        d.setShape(GradientDrawable.RECTANGLE);
        d.setCornerRadius(dp(999));
        d.setColor(colorInt);
        return d;
    }

    private GradientDrawable createCircleDrawable(@ColorInt int colorInt) {
        GradientDrawable d = new GradientDrawable();
        d.setShape(GradientDrawable.OVAL);
        d.setColor(colorInt);
        return d;
    }

    private void applyRowRipple(View view) {
        TypedValue out = new TypedValue();
        if (getTheme().resolveAttribute(android.R.attr.selectableItemBackground, out, true)) {
            view.setForeground(ContextCompat.getDrawable(this, out.resourceId));
        }
    }

    private boolean animationsEnabled() {
        return ValueAnimator.areAnimatorsEnabled();
    }

    @ColorInt
    private int color(@ColorRes int resId) {
        return ContextCompat.getColor(this, resId);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
