package com.wsttxm.riskenginesdk.demo.ui;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.graphics.SweepGradient;
import android.graphics.Typeface;
import android.util.AttributeSet;
import android.view.Choreographer;
import android.view.View;

import androidx.annotation.ColorInt;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.dynamicanimation.animation.FloatValueHolder;
import androidx.dynamicanimation.animation.SpringAnimation;
import androidx.dynamicanimation.animation.SpringForce;

import com.wsttxm.riskenginesdk.demo.R;

/**
 * Dual-mode precision gauge view:
 * - EMBLEM mode: Serene RiskEngine shield-star emblem with display-synced orbital sweep during scan.
 * - SCORE mode: Apple Health-inspired circular score arc with spring-driven sweep & tabular numerals.
 */
public class RiskGaugeView extends View {

    public static final int MODE_EMBLEM = 0;
    public static final int MODE_SCORE = 1;

    private int mode = MODE_EMBLEM;
    private boolean scanning = false;

    private final Paint trackPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint outerHaloPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint arcPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint emblemPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint scoreTextPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint maxTextPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    private final RectF arcBounds = new RectF();
    private final Path shieldPath = new Path();
    private final Path transformedShield = new Path();
    private final Matrix emblemMatrix = new Matrix();

    private float density;
    private float displayedProgress = 0f;
    private float targetProgress = 0f;
    private int scoreValue = 0;
    private int maxScoreValue = 18;
    @ColorInt
    private int accentColor;

    private float orbitAngle = -90f;
    private float pulsePhase = 0f;
    private long lastFrameNanos = 0L;
    private boolean frameCallbackActive = false;

    private final FloatValueHolder progressHolder = new FloatValueHolder(0f);
    private SpringAnimation progressSpring;

    private final Choreographer.FrameCallback frameCallback = new Choreographer.FrameCallback() {
        @Override
        public void doFrame(long frameTimeNanos) {
            if (!frameCallbackActive || !isAttachedToWindow()) {
                frameCallbackActive = false;
                return;
            }
            if (lastFrameNanos != 0L) {
                float dt = Math.min(0.05f, (frameTimeNanos - lastFrameNanos) / 1_000_000_000f);
                orbitAngle = (orbitAngle + dt * 260f) % 360f;
                pulsePhase = (pulsePhase + dt * 3.2f) % (float) (Math.PI * 2.0);
            }
            lastFrameNanos = frameTimeNanos;
            invalidate();
            Choreographer.getInstance().postFrameCallback(this);
        }
    };

    public RiskGaugeView(Context context) {
        super(context);
        init(context);
    }

    public RiskGaugeView(Context context, @Nullable AttributeSet attrs) {
        super(context, attrs);
        init(context);
    }

    public RiskGaugeView(Context context, @Nullable AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context);
    }

    private void init(Context context) {
        density = context.getResources().getDisplayMetrics().density;
        accentColor = ContextCompat.getColor(context, R.color.accent);

        trackPaint.setStyle(Paint.Style.STROKE);
        trackPaint.setStrokeCap(Paint.Cap.ROUND);
        trackPaint.setColor(ContextCompat.getColor(context, R.color.track));

        outerHaloPaint.setStyle(Paint.Style.FILL);
        outerHaloPaint.setColor(ContextCompat.getColor(context, R.color.gauge_idle_fill));

        arcPaint.setStyle(Paint.Style.STROKE);
        arcPaint.setStrokeCap(Paint.Cap.ROUND);
        arcPaint.setColor(accentColor);

        emblemPaint.setStyle(Paint.Style.FILL);
        emblemPaint.setColor(ContextCompat.getColor(context, R.color.text_primary));

        scoreTextPaint.setTextAlign(Paint.Align.CENTER);
        scoreTextPaint.setColor(ContextCompat.getColor(context, R.color.text_primary));
        scoreTextPaint.setTypeface(Typeface.create("sans-serif", Typeface.BOLD));
        scoreTextPaint.setFontFeatureSettings("tnum");

        maxTextPaint.setTextAlign(Paint.Align.CENTER);
        maxTextPaint.setColor(ContextCompat.getColor(context, R.color.text_tertiary));
        maxTextPaint.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        maxTextPaint.setFontFeatureSettings("tnum");

        buildShieldPath();
        initSpring();
    }

    private void initSpring() {
        progressSpring = new SpringAnimation(progressHolder);
        SpringForce force = new SpringForce(0f);
        force.setDampingRatio(0.92f);
        force.setStiffness(220f);
        progressSpring.setSpring(force);
        progressSpring.setMinimumVisibleChange(0.002f);
        progressSpring.addUpdateListener((animation, value, velocity) -> {
            displayedProgress = Math.max(0f, Math.min(1f, value));
            invalidate();
        });
    }

    /**
     * Exact same RiskEngine sculptural shield + 4-point star aperture geometry in 108x108 space.
     */
    private void buildShieldPath() {
        shieldPath.reset();
        shieldPath.setFillType(Path.FillType.EVEN_ODD);

        shieldPath.moveTo(54.0f, 32.2f);
        shieldPath.cubicTo(60.8f, 32.2f, 67.8f, 34.4f, 72.3f, 37.3f);
        shieldPath.cubicTo(73.5f, 38.1f, 74.2f, 39.4f, 74.2f, 40.9f);
        shieldPath.lineTo(74.2f, 51.6f);
        shieldPath.cubicTo(74.2f, 63.8f, 65.7f, 72.3f, 55.6f, 76.2f);
        shieldPath.cubicTo(54.6f, 76.7f, 53.4f, 76.7f, 52.4f, 76.2f);
        shieldPath.cubicTo(42.3f, 72.3f, 33.8f, 63.8f, 33.8f, 51.6f);
        shieldPath.lineTo(33.8f, 40.9f);
        shieldPath.cubicTo(33.8f, 39.4f, 34.5f, 38.1f, 35.7f, 37.3f);
        shieldPath.cubicTo(40.2f, 34.4f, 47.2f, 32.2f, 54.0f, 32.2f);
        shieldPath.close();

        shieldPath.moveTo(54.0f, 42.0f);
        shieldPath.cubicTo(54.6f, 49.4f, 58.1f, 52.9f, 65.5f, 53.5f);
        shieldPath.cubicTo(58.1f, 54.1f, 54.6f, 57.6f, 54.0f, 65.0f);
        shieldPath.cubicTo(53.4f, 57.6f, 49.9f, 54.1f, 42.5f, 53.5f);
        shieldPath.cubicTo(49.9f, 52.9f, 53.4f, 49.4f, 54.0f, 42.0f);
        shieldPath.close();
    }

    public void setMode(int mode) {
        this.mode = mode;
        if (mode != MODE_EMBLEM) {
            stopOrbit();
        }
        invalidate();
    }

    public void setScanning(boolean scanning) {
        this.scanning = scanning;
        if (scanning && mode == MODE_EMBLEM) {
            startOrbit();
        } else {
            stopOrbit();
        }
        invalidate();
    }

    public void setScore(int score, int maxScore, @ColorInt int color, boolean animate) {
        this.mode = MODE_SCORE;
        stopOrbit();
        this.scoreValue = Math.max(0, score);
        this.maxScoreValue = Math.max(1, maxScore);
        this.accentColor = color;
        this.targetProgress = Math.max(0f, Math.min(1f, (float) scoreValue / (float) maxScoreValue));
        // Even for score 0 (SAFE), show a subtle complete emerald ring or crisp full safe arc?
        // Actually for SAFE (score == 0), show a calm full ring in emerald so it reads as "100% protected"
        float visualArc = (scoreValue == 0 && color == ContextCompat.getColor(getContext(), R.color.risk_safe))
                ? 1f
                : Math.max(targetProgress, scoreValue > 0 ? 0.08f : 0f);

        if (animate && ValueAnimator.areAnimatorsEnabled()) {
            progressSpring.cancel();
            progressHolder.setValue(0f);
            displayedProgress = 0f;
            progressSpring.animateToFinalPosition(visualArc);
        } else {
            progressSpring.cancel();
            displayedProgress = visualArc;
            progressHolder.setValue(visualArc);
            invalidate();
        }
    }

    private void startOrbit() {
        if (frameCallbackActive || !isAttachedToWindow()) {
            return;
        }
        frameCallbackActive = true;
        lastFrameNanos = 0L;
        Choreographer.getInstance().postFrameCallback(frameCallback);
    }

    private void stopOrbit() {
        frameCallbackActive = false;
        Choreographer.getInstance().removeFrameCallback(frameCallback);
    }

    @Override
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (scanning && mode == MODE_EMBLEM) {
            startOrbit();
        }
    }

    @Override
    protected void onDetachedFromWindow() {
        stopOrbit();
        if (progressSpring != null) {
            progressSpring.cancel();
        }
        super.onDetachedFromWindow();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float w = getWidth();
        float h = getHeight();
        float size = Math.min(w, h);
        if (size <= 0f) {
            return;
        }
        float cx = w * 0.5f;
        float cy = h * 0.5f;

        if (mode == MODE_EMBLEM) {
            drawEmblemMode(canvas, cx, cy, size);
        } else {
            drawScoreMode(canvas, cx, cy, size);
        }
    }

    private void drawEmblemMode(Canvas canvas, float cx, float cy, float size) {
        float stroke = Math.max(2f * density, size * 0.028f);
        float radius = size * 0.44f;

        // Soft circular surface well
        outerHaloPaint.setColor(ContextCompat.getColor(getContext(), R.color.gauge_idle_fill));
        canvas.drawCircle(cx, cy, radius, outerHaloPaint);

        // Outer hairline ring
        trackPaint.setStrokeWidth(stroke);
        trackPaint.setColor(ContextCompat.getColor(getContext(), R.color.gauge_idle_ring));
        canvas.drawCircle(cx, cy, radius, trackPaint);

        // Scanning luminous sweep (respecting reduced motion)
        if (scanning) {
            arcBounds.set(cx - radius, cy - radius, cx + radius, cy + radius);
            if (ValueAnimator.areAnimatorsEnabled()) {
                arcPaint.setStrokeWidth(stroke * 1.35f);
                int transparentAccent = accentColor & 0x00FFFFFF;
                SweepGradient shader = new SweepGradient(
                        cx, cy,
                        new int[]{transparentAccent, transparentAccent, accentColor},
                        new float[]{0f, 0.58f, 1f}
                );
                Matrix rot = new Matrix();
                rot.postRotate(orbitAngle, cx, cy);
                shader.setLocalMatrix(rot);
                arcPaint.setShader(shader);
                canvas.drawArc(arcBounds, orbitAngle + 210f, 145f, false, arcPaint);
                arcPaint.setShader(null);
            } else {
                // Reduced motion: gentle static accent ring
                arcPaint.setShader(null);
                arcPaint.setStrokeWidth(stroke * 1.2f);
                arcPaint.setColor(accentColor);
                arcPaint.setAlpha(190);
                canvas.drawCircle(cx, cy, radius, arcPaint);
                arcPaint.setAlpha(255);
            }
        }

        // Centered RiskEngine minimalist shield-star mark
        float glyphScale = (size * 0.72f) / 108f;
        emblemMatrix.reset();
        emblemMatrix.postTranslate(-54f, -54f);
        emblemMatrix.postScale(glyphScale, glyphScale);
        emblemMatrix.postTranslate(cx, cy);
        shieldPath.transform(emblemMatrix, transformedShield);

        emblemPaint.setColor(ContextCompat.getColor(getContext(),
                scanning ? R.color.accent : R.color.text_primary));
        if (scanning && ValueAnimator.areAnimatorsEnabled()) {
            float alphaFactor = 0.80f + 0.20f * (float) Math.sin(pulsePhase);
            emblemPaint.setAlpha((int) (255 * alphaFactor));
        } else {
            emblemPaint.setAlpha(255);
        }
        canvas.drawPath(transformedShield, emblemPaint);
        emblemPaint.setAlpha(255);
    }

    private void drawScoreMode(Canvas canvas, float cx, float cy, float size) {
        float stroke = Math.max(6f * density, size * 0.088f);
        float radius = (size - stroke) * 0.5f - 2f * density;
        arcBounds.set(cx - radius, cy - radius, cx + radius, cy + radius);

        trackPaint.setStrokeWidth(stroke);
        trackPaint.setColor(ContextCompat.getColor(getContext(), R.color.track));
        canvas.drawArc(arcBounds, 0f, 360f, false, trackPaint);

        if (displayedProgress > 0.001f) {
            arcPaint.setShader(null);
            arcPaint.setStrokeWidth(stroke);
            arcPaint.setColor(accentColor);
            float sweep = Math.min(360f, displayedProgress * 360f);
            canvas.drawArc(arcBounds, -90f, sweep, false, arcPaint);
        }

        // Optical tabular numeral typography
        scoreTextPaint.setTextSize(size * 0.30f);
        scoreTextPaint.setColor(ContextCompat.getColor(getContext(), R.color.text_primary));
        maxTextPaint.setTextSize(size * 0.135f);
        maxTextPaint.setColor(ContextCompat.getColor(getContext(), R.color.text_tertiary));

        String scoreStr = String.valueOf(scoreValue);
        String maxStr = "/ " + maxScoreValue;

        Paint.FontMetrics scoreFm = scoreTextPaint.getFontMetrics();
        Paint.FontMetrics maxFm = maxTextPaint.getFontMetrics();
        float scoreH = scoreFm.descent - scoreFm.ascent;
        float maxH = maxFm.descent - maxFm.ascent;
        float gap = size * 0.015f;
        float totalH = scoreH + gap + maxH;
        float topY = cy - totalH * 0.5f;

        float scoreBaseline = topY - scoreFm.ascent - size * 0.02f;
        float maxBaseline = topY + scoreH + gap - maxFm.ascent - size * 0.03f;

        canvas.drawText(scoreStr, cx, scoreBaseline, scoreTextPaint);
        canvas.drawText(maxStr, cx, maxBaseline, maxTextPaint);
    }
}
