package com.wsttxm.riskenginesdk.demo.ui;

import android.content.Context;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.annotation.ColorInt;
import androidx.annotation.ColorRes;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;

import com.wsttxm.riskenginesdk.demo.R;
import com.wsttxm.riskenginesdk.model.DevicePosture;
import com.wsttxm.riskenginesdk.model.ThreatEvent;

import java.text.DateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Apple Fluid gesture-driven drawer surfacing real-time {@code ThreatListener}
 * (including post-init runtime tamper alerts) and {@code DeviceStateListener} posture updates.
 */
public final class ThreatStreamDrawer {

    public static final int MAX_ENTRIES = 50;

    public static final class StreamEntry {
        public final ThreatEvent event;
        public final boolean runtimeTamper;
        public final long receivedAtMs;

        StreamEntry(ThreatEvent event, boolean runtimeTamper, long receivedAtMs) {
            this.event = event;
            this.runtimeTamper = runtimeTamper;
            this.receivedAtMs = receivedAtMs;
        }
    }

    private final Context ctx;
    private final ReportFormatter formatter;
    private final FluidDetailSheet sheet;
    private final View drawerContainer;
    private final ScrollView scrollView;
    private final LinearLayout bodyContainer;
    private final TextView tvBadge;
    private final TextView btnClear;

    private final Object lock = new Object();
    private final Deque<StreamEntry> entries = new ArrayDeque<>();
    @Nullable
    private DevicePosture latestPosture;
    private long latestPostureAtMs = 0L;
    private int runtimeTamperCount = 0;

    @Nullable
    private Runnable onClearedCallback;

    public ThreatStreamDrawer(
            Context context,
            ReportFormatter formatter,
            View overlayRoot,
            View scrimView,
            View drawerContainer,
            View dragHeader,
            ScrollView scrollView,
            LinearLayout bodyContainer,
            TextView tvBadge,
            TextView btnClear,
            ImageButton btnClose,
            @Nullable View backgroundContent) {
        this.ctx = context;
        this.formatter = formatter;
        this.drawerContainer = drawerContainer;
        this.scrollView = scrollView;
        this.bodyContainer = bodyContainer;
        this.tvBadge = tvBadge;
        this.btnClear = btnClear;
        this.sheet = new FluidDetailSheet(
                overlayRoot, scrimView, drawerContainer, dragHeader, scrollView, backgroundContent);

        SpringTouchHelper.attachCompact(btnClose);
        SpringTouchHelper.attachCompact(btnClear);
        btnClose.setOnClickListener(v -> dismiss());
        btnClear.setOnClickListener(v -> {
            clear();
            render();
            if (onClearedCallback != null) {
                onClearedCallback.run();
            }
        });
    }

    public void setOnClearedCallback(@Nullable Runnable callback) {
        this.onClearedCallback = callback;
    }

    public void applyInsets(int statusBarInsetPx, int navBarInsetPx) {
        bodyContainer.setPadding(dp(22), dp(18), dp(22), navBarInsetPx + dp(28));
        ViewGroup.LayoutParams rawLp = drawerContainer.getLayoutParams();
        if (rawLp instanceof FrameLayout.LayoutParams) {
            FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) rawLp;
            lp.topMargin = statusBarInsetPx + dp(56);
            drawerContainer.setLayoutParams(lp);
        }
    }

    /** Records an incoming threat or runtime tamper event (thread-safe). */
    public void recordThreat(ThreatEvent event, boolean runtimeTamper) {
        if (event == null) {
            return;
        }
        boolean isRuntime = runtimeTamper || event.isRuntimeTamper();
        synchronized (lock) {
            entries.addFirst(new StreamEntry(event, isRuntime, System.currentTimeMillis()));
            if (isRuntime) {
                runtimeTamperCount++;
            }
            while (entries.size() > MAX_ENTRIES) {
                StreamEntry removed = entries.removeLast();
                if (removed.runtimeTamper && runtimeTamperCount > 0) {
                    runtimeTamperCount--;
                }
            }
        }
    }

    /** Records an evaluated DevicePosture snapshot (thread-safe). */
    public void recordPosture(DevicePosture posture) {
        if (posture == null) {
            return;
        }
        synchronized (lock) {
            latestPosture = posture;
            latestPostureAtMs = System.currentTimeMillis();
        }
    }

    public void clear() {
        synchronized (lock) {
            entries.clear();
            runtimeTamperCount = 0;
        }
    }

    public int getEventCount() {
        synchronized (lock) {
            return entries.size();
        }
    }

    public int getRuntimeTamperCount() {
        synchronized (lock) {
            return runtimeTamperCount;
        }
    }

    public boolean isShowing() {
        return sheet.isShowing();
    }

    public void show() {
        render();
        ViewGroup.LayoutParams lp = scrollView.getLayoutParams();
        lp.height = ViewGroup.LayoutParams.WRAP_CONTENT;
        scrollView.setLayoutParams(lp);
        sheet.show();
        updateCappedScrollHeight();
    }

    public void dismiss() {
        sheet.dismiss();
    }

    /** Re-renders live stream content if the drawer is currently open (call on UI thread). */
    public void refreshIfShowing() {
        if (sheet.isShowing()) {
            render();
            updateCappedScrollHeight();
        }
    }

    private void updateCappedScrollHeight() {
        scrollView.post(() -> {
            View child = scrollView.getChildAt(0);
            if (child == null) {
                return;
            }
            DisplayMetrics dm = ctx.getResources().getDisplayMetrics();
            int maxScrollH = Math.round(dm.heightPixels * 0.65f);
            int desired = Math.min(child.getHeight(), maxScrollH);
            if (desired > 0) {
                ViewGroup.LayoutParams cur = scrollView.getLayoutParams();
                if (cur.height != desired) {
                    cur.height = desired;
                    scrollView.setLayoutParams(cur);
                }
            }
        });
    }

    private void render() {
        List<StreamEntry> snapshot;
        DevicePosture posture;
        long postureAtMs;
        int runtimeCount;
        synchronized (lock) {
            snapshot = new ArrayList<>(entries);
            posture = latestPosture;
            postureAtMs = latestPostureAtMs;
            runtimeCount = runtimeTamperCount;
        }

        if (snapshot.isEmpty()) {
            tvBadge.setText(ctx.getString(R.string.threat_stream_badge_idle));
            tvBadge.setTextColor(color(R.color.accent));
            tvBadge.setBackground(createPillDrawable(color(R.color.accent_soft)));
            btnClear.setVisibility(View.GONE);
        } else {
            tvBadge.setText(ctx.getString(R.string.threat_stream_badge_live, snapshot.size()));
            @ColorInt int badgeFg = runtimeCount > 0 ? color(R.color.risk_deadly) : color(R.color.risk_high);
            @ColorInt int badgeBg = runtimeCount > 0 ? color(R.color.risk_deadly_bg) : color(R.color.risk_high_bg);
            tvBadge.setTextColor(badgeFg);
            tvBadge.setBackground(createPillDrawable(badgeBg));
            btnClear.setVisibility(View.VISIBLE);
        }

        bodyContainer.removeAllViews();

        // 1. Latest DevicePosture snapshot (DeviceStateListener)
        addSectionTitle(ctx.getString(R.string.threat_stream_section_posture), false);
        if (posture == null) {
            bodyContainer.addView(createText(
                    ctx.getString(R.string.threat_stream_empty_posture),
                    13f, R.color.text_secondary, Typeface.NORMAL));
        } else {
            LinearLayout postureWell = createWell();
            String compact = formatter.postureCompactSummary(posture);
            if (!compact.isEmpty()) {
                TextView tvSummary = createText(compact, 13.5f, R.color.text_primary, Typeface.BOLD);
                tvSummary.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
                postureWell.addView(tvSummary);
            }
            if (postureAtMs > 0L) {
                String ts = DateFormat.getTimeInstance(DateFormat.MEDIUM, Locale.getDefault())
                        .format(new Date(postureAtMs));
                TextView tvTs = createText("更新于 " + ts, 11.5f, R.color.text_tertiary, Typeface.NORMAL);
                LinearLayout.LayoutParams tlp = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                tlp.topMargin = dp(3);
                tlp.bottomMargin = dp(8);
                tvTs.setLayoutParams(tlp);
                postureWell.addView(tvTs);
            }
            for (Map.Entry<String, String> row : formatter.postureDetailRows(posture).entrySet()) {
                addKeyValue(postureWell, row.getKey(), row.getValue());
            }
            bodyContainer.addView(postureWell);
        }

        // 2. Real-time ThreatEvent stream (ThreatListener)
        addSectionTitle(ctx.getString(R.string.threat_stream_section_events), true);
        if (snapshot.isEmpty()) {
            bodyContainer.addView(createText(
                    ctx.getString(R.string.threat_stream_empty_events),
                    13f, R.color.text_secondary, Typeface.NORMAL));
        } else {
            DateFormat timeFmt = DateFormat.getTimeInstance(DateFormat.MEDIUM, Locale.getDefault());
            for (int i = 0; i < snapshot.size(); i++) {
                bodyContainer.addView(createEventCard(snapshot.get(i), timeFmt, i > 0));
            }
        }
    }

    private View createEventCard(StreamEntry entry, DateFormat timeFmt, boolean topMargin) {
        ThreatEvent event = entry.event;
        LinearLayout card = createWell();
        if (topMargin) {
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            lp.topMargin = dp(10);
            card.setLayoutParams(lp);
        }

        @ColorInt int levelColor = color(formatter.riskColorRes(event.getRiskLevel()));
        @ColorInt int levelBg = color(formatter.riskBgRes(event.getRiskLevel()));

        LinearLayout header = new LinearLayout(ctx);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);

        View dot = new View(ctx);
        LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dp(7), dp(7));
        dotLp.setMarginEnd(dp(8));
        dot.setLayoutParams(dotLp);
        dot.setBackground(createCircleDrawable(levelColor));
        header.addView(dot);

        TextView tvTitle = createText(
                formatter.detectorTitle(event.getDetectorName()),
                14f, R.color.text_primary, Typeface.BOLD);
        tvTitle.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        tvTitle.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        header.addView(tvTitle);

        if (entry.runtimeTamper) {
            TextView rtPill = createPill(
                    ctx.getString(R.string.threat_stream_runtime_tamper_tag),
                    color(R.color.risk_deadly), color(R.color.risk_deadly_bg));
            LinearLayout.LayoutParams rlp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            rlp.setMarginStart(dp(6));
            rtPill.setLayoutParams(rlp);
            header.addView(rtPill);
        }

        TextView levelPill = createPill(formatter.riskLabel(event.getRiskLevel()), levelColor, levelBg);
        LinearLayout.LayoutParams llp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        llp.setMarginStart(dp(6));
        levelPill.setLayoutParams(llp);
        header.addView(levelPill);

        card.addView(header);

        TextView tvSummary = createText(
                formatter.threatEventSummary(event),
                13f, R.color.text_primary, Typeface.NORMAL);
        tvSummary.setLineSpacing(dp(2), 1f);
        LinearLayout.LayoutParams slp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        slp.topMargin = dp(7);
        tvSummary.setLayoutParams(slp);
        card.addView(tvSummary);

        String metaText = timeFmt.format(new Date(entry.receivedAtMs))
                + " · " + event.getScanTier().name()
                + " · 强度 " + event.getScore();
        if (!event.getEvidenceFamilies().isEmpty()) {
            List<String> familyLabels = new ArrayList<>(event.getEvidenceFamilies().size());
            for (String family : event.getEvidenceFamilies()) {
                familyLabels.add(formatter.evidenceFamilyLabel(family));
            }
            metaText += " · " + String.join(" / ", familyLabels);
        }
        TextView tvMeta = createText(metaText, 11.5f, R.color.text_tertiary, Typeface.NORMAL);
        tvMeta.setFontFeatureSettings("tnum");
        LinearLayout.LayoutParams mlp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        mlp.topMargin = dp(5);
        tvMeta.setLayoutParams(mlp);
        card.addView(tvMeta);

        return card;
    }

    private void addSectionTitle(String title, boolean topMargin) {
        TextView tv = createText(title, 12.5f, R.color.text_secondary, Typeface.BOLD);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = topMargin ? dp(18) : 0;
        lp.bottomMargin = dp(8);
        tv.setLayoutParams(lp);
        bodyContainer.addView(tv);
    }

    private LinearLayout createWell() {
        LinearLayout well = new LinearLayout(ctx);
        well.setOrientation(LinearLayout.VERTICAL);
        well.setBackgroundResource(R.drawable.bg_code_block);
        well.setPadding(dp(14), dp(12), dp(14), dp(12));
        return well;
    }

    private void addKeyValue(LinearLayout container, String key, String value) {
        LinearLayout row = new LinearLayout(ctx);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(4), 0, dp(4));

        TextView tvKey = createText(key, 12.5f, R.color.text_secondary, Typeface.NORMAL);
        tvKey.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(tvKey);

        TextView tvVal = createText(value, 12.5f, R.color.text_primary, Typeface.BOLD);
        tvVal.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        tvVal.setFontFeatureSettings("tnum");
        row.addView(tvVal);
        container.addView(row);
    }

    private TextView createPill(String text, @ColorInt int textColor, @ColorInt int bgColor) {
        TextView pill = new TextView(ctx);
        pill.setText(text);
        pill.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10.5f);
        pill.setTextColor(textColor);
        pill.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        pill.setBackground(createPillDrawable(bgColor));
        pill.setPadding(dp(8), dp(2), dp(8), dp(2));
        return pill;
    }

    private TextView createText(String text, float sp, @ColorRes int colorRes, int style) {
        TextView tv = new TextView(ctx);
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

    @ColorInt
    private int color(@ColorRes int resId) {
        return ContextCompat.getColor(ctx, resId);
    }

    private int dp(int value) {
        return Math.round(value * ctx.getResources().getDisplayMetrics().density);
    }
}
