package com.wsttxm.riskenginesdk.demo.ui;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.util.AttributeSet;
import android.view.HapticFeedbackConstants;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;

import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.dynamicanimation.animation.FloatValueHolder;
import androidx.dynamicanimation.animation.SpringAnimation;
import androidx.dynamicanimation.animation.SpringForce;

import com.wsttxm.riskenginesdk.demo.R;

/**
 * Apple-style Segmented Control with a physically spring-animated sliding capsule thumb,
 * direct 1:1 drag manipulation with rubber-banding at ends, velocity handoff, and haptics.
 */
public class SegmentedControlView extends View {

    public interface OnSegmentSelectedListener {
        void onSegmentSelected(int index);
    }

    private final Paint trackPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint thumbPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);

    private final RectF trackRect = new RectF();
    private final RectF thumbRect = new RectF();

    private String[] labels = new String[]{"安全检测", "设备指纹"};
    private int selectedIndex = 0;
    private float thumbPosition = 0f; // continuous 0..(n-1)
    private float density;
    private float paddingPx;

    private final FloatValueHolder thumbHolder = new FloatValueHolder(0f);
    private SpringAnimation thumbSpring;
    private OnSegmentSelectedListener listener;

    private VelocityTracker velocityTracker;
    private boolean dragging = false;
    private float downX = 0f;
    private float downThumbPos = 0f;
    private float touchSlopPx;

    public SegmentedControlView(Context context) {
        super(context);
        init(context);
    }

    public SegmentedControlView(Context context, @Nullable AttributeSet attrs) {
        super(context, attrs);
        init(context);
    }

    public SegmentedControlView(Context context, @Nullable AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context);
    }

    private void init(Context context) {
        density = context.getResources().getDisplayMetrics().density;
        paddingPx = 4f * density;
        touchSlopPx = 8f * density;

        setLayerType(LAYER_TYPE_SOFTWARE, null); // enables soft thumb elevation shadow cleanly

        trackPaint.setStyle(Paint.Style.FILL);
        trackPaint.setColor(ContextCompat.getColor(context, R.color.surface_subtle));

        thumbPaint.setStyle(Paint.Style.FILL);
        thumbPaint.setColor(ContextCompat.getColor(context, R.color.surface_segment_thumb));
        thumbPaint.setShadowLayer(4f * density, 0f, 1.5f * density, 0x1A000000);

        textPaint.setTextAlign(Paint.Align.CENTER);
        textPaint.setTextSize(android.util.TypedValue.applyDimension(
                android.util.TypedValue.COMPLEX_UNIT_SP, 14f, context.getResources().getDisplayMetrics()));
        textPaint.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));

        thumbSpring = new SpringAnimation(thumbHolder);
        SpringForce force = new SpringForce(0f);
        force.setDampingRatio(0.86f);
        force.setStiffness(480f);
        thumbSpring.setSpring(force);
        thumbSpring.setMinimumVisibleChange(0.002f);
        thumbSpring.addUpdateListener((animation, value, velocity) -> {
            thumbPosition = value;
            invalidate();
        });

        setClickable(true);
        setFocusable(true);
    }

    public void setLabels(String... newLabels) {
        if (newLabels == null || newLabels.length < 2) {
            return;
        }
        this.labels = newLabels;
        if (selectedIndex >= labels.length) {
            selectedIndex = 0;
            thumbPosition = 0f;
            thumbHolder.setValue(0f);
        }
        invalidate();
    }

    public void setOnSegmentSelectedListener(@Nullable OnSegmentSelectedListener listener) {
        this.listener = listener;
    }

    public int getSelectedIndex() {
        return selectedIndex;
    }

    public void setSelectedIndex(int index, boolean animate, boolean notify) {
        int clamped = Math.max(0, Math.min(labels.length - 1, index));
        boolean changed = clamped != selectedIndex;
        selectedIndex = clamped;

        if (animate && ValueAnimator.areAnimatorsEnabled()) {
            thumbSpring.animateToFinalPosition(clamped);
        } else {
            thumbSpring.cancel();
            thumbPosition = clamped;
            thumbHolder.setValue(clamped);
            invalidate();
        }
        if (changed && notify && listener != null) {
            performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK);
            listener.onSegmentSelected(selectedIndex);
        }
    }

    @Override
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int desiredH = Math.round(44f * density);
        int h = resolveSize(desiredH, heightMeasureSpec);
        int w = resolveSize(Math.round(280f * density), widthMeasureSpec);
        setMeasuredDimension(w, h);
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float w = getWidth();
        float h = getHeight();
        if (w <= 0f || h <= 0f || labels.length == 0) {
            return;
        }

        float trackRadius = h * 0.5f;
        trackRect.set(0f, 0f, w, h);
        canvas.drawRoundRect(trackRect, trackRadius, trackRadius, trackPaint);

        float innerW = w - paddingPx * 2f;
        float segmentW = innerW / labels.length;
        float thumbLeft = paddingPx + thumbPosition * segmentW;
        float thumbRadius = (h - paddingPx * 2f) * 0.5f;
        thumbRect.set(thumbLeft, paddingPx, thumbLeft + segmentW, h - paddingPx);
        canvas.drawRoundRect(thumbRect, thumbRadius, thumbRadius, thumbPaint);

        int activeColor = ContextCompat.getColor(getContext(), R.color.text_primary);
        int inactiveColor = ContextCompat.getColor(getContext(), R.color.text_secondary);

        Paint.FontMetrics fm = textPaint.getFontMetrics();
        float textBaseline = h * 0.5f - (fm.ascent + fm.descent) * 0.5f;

        for (int i = 0; i < labels.length; i++) {
            float centerX = paddingPx + (i + 0.5f) * segmentW;
            float distance = Math.min(1f, Math.abs(thumbPosition - i));
            textPaint.setColor(blendColor(activeColor, inactiveColor, distance));
            textPaint.setTypeface(distance < 0.5f
                    ? Typeface.create("sans-serif-medium", Typeface.BOLD)
                    : Typeface.create("sans-serif-medium", Typeface.NORMAL));
            canvas.drawText(labels[i], centerX, textBaseline, textPaint);
        }
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        float innerW = getWidth() - paddingPx * 2f;
        if (innerW <= 0f || labels.length == 0) {
            return super.onTouchEvent(event);
        }
        float segmentW = innerW / labels.length;

        switch (event.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                thumbSpring.cancel(); // Interruptible mid-flight (Apple Design §3)
                downX = event.getX();
                downThumbPos = thumbPosition;
                dragging = false;
                if (velocityTracker == null) {
                    velocityTracker = VelocityTracker.obtain();
                } else {
                    velocityTracker.clear();
                }
                velocityTracker.addMovement(event);
                getParent().requestDisallowInterceptTouchEvent(true);
                return true;

            case MotionEvent.ACTION_MOVE:
                if (velocityTracker != null) {
                    velocityTracker.addMovement(event);
                }
                float dx = event.getX() - downX;
                if (!dragging && Math.abs(dx) > touchSlopPx) {
                    dragging = true;
                }
                if (dragging) {
                    float rawPos = downThumbPos + dx / segmentW;
                    float maxPos = labels.length - 1;
                    // Rubber-band at ends (Apple Design §9)
                    if (rawPos < 0f) {
                        thumbPosition = -rubberband(-rawPos, 0.35f);
                    } else if (rawPos > maxPos) {
                        thumbPosition = maxPos + rubberband(rawPos - maxPos, 0.35f);
                    } else {
                        thumbPosition = rawPos;
                    }
                    thumbHolder.setValue(thumbPosition);
                    invalidate();
                }
                return true;

            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_CANCEL:
                getParent().requestDisallowInterceptTouchEvent(false);
                float velocitySegPerSec = 0f;
                if (velocityTracker != null) {
                    velocityTracker.addMovement(event);
                    velocityTracker.computeCurrentVelocity(1000);
                    velocitySegPerSec = velocityTracker.getXVelocity() / segmentW;
                    velocityTracker.recycle();
                    velocityTracker = null;
                }
                int target;
                if (dragging) {
                    // Momentum projection (Apple Design §6)
                    float projected = thumbPosition + (velocitySegPerSec / 1000f) * 0.992f / (1f - 0.992f) * 0.25f;
                    target = Math.max(0, Math.min(labels.length - 1, Math.round(projected)));
                } else {
                    float rel = (event.getX() - paddingPx) / segmentW;
                    target = Math.max(0, Math.min(labels.length - 1, (int) Math.floor(rel)));
                }
                dragging = false;
                if (ValueAnimator.areAnimatorsEnabled()) {
                    thumbSpring.setStartVelocity(velocitySegPerSec);
                }
                setSelectedIndex(target, true, true);
                performClick();
                return true;

            default:
                return super.onTouchEvent(event);
        }
    }

    @Override
    public boolean performClick() {
        return super.performClick();
    }

    private static float rubberband(float overshoot, float dimension) {
        return (overshoot * dimension * 0.55f) / (dimension + 0.55f * Math.abs(overshoot));
    }

    private static int blendColor(int c1, int c2, float ratio) {
        float inv = 1f - ratio;
        int a = Math.round(((c1 >>> 24) & 0xFF) * inv + ((c2 >>> 24) & 0xFF) * ratio);
        int r = Math.round(((c1 >>> 16) & 0xFF) * inv + ((c2 >>> 16) & 0xFF) * ratio);
        int g = Math.round(((c1 >>> 8) & 0xFF) * inv + ((c2 >>> 8) & 0xFF) * ratio);
        int b = Math.round((c1 & 0xFF) * inv + (c2 & 0xFF) * ratio);
        return (a << 24) | (r << 16) | (g << 8) | b;
    }
}
