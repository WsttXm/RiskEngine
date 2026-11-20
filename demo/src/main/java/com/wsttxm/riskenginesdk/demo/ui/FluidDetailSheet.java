package com.wsttxm.riskenginesdk.demo.ui;

import android.animation.ValueAnimator;
import android.annotation.SuppressLint;
import android.view.HapticFeedbackConstants;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ScrollView;

import androidx.annotation.Nullable;
import androidx.dynamicanimation.animation.DynamicAnimation;
import androidx.dynamicanimation.animation.SpringAnimation;
import androidx.dynamicanimation.animation.SpringForce;

/**
 * Apple Design §2–§9 & §12–§14:
 * Gesture-driven draggable sheet with 1:1 pointer tracking, grab-offset fidelity,
 * mid-flight interruptibility, rubber-banding at top bound, exponential momentum projection,
 * velocity handoff into SpringAnimation, continuous scrim + background depth scale-back,
 * and reduced-motion cross-fade fallback.
 */
public final class FluidDetailSheet {

    private static final float DECELERATION_RATE = 0.996f;
    private static final float RUBBERBAND_CONSTANT = 0.55f;
    private static final float BACKGROUND_MIN_SCALE = 0.968f;

    private final View overlayRoot;
    private final View scrimView;
    private final View sheetContainer;
    private final ScrollView scrollView;
    @Nullable
    private final View backgroundContent;

    private final SpringAnimation translateSpring;
    private boolean isShowing = false;
    private boolean isDismissing = false;
    private float sheetHeight = 0f;
    private float touchSlopPx;

    private VelocityTracker velocityTracker;
    private boolean dragging = false;
    private float downRawY = 0f;
    private float startTranslationY = 0f;
    private boolean dragAllowedFromScroll = false;

    public FluidDetailSheet(
            View overlayRoot,
            View scrimView,
            View sheetContainer,
            View dragHeader,
            ScrollView scrollView,
            @Nullable View backgroundContent) {
        this.overlayRoot = overlayRoot;
        this.scrimView = scrimView;
        this.sheetContainer = sheetContainer;
        this.scrollView = scrollView;
        this.backgroundContent = backgroundContent;
        this.touchSlopPx = 8f * overlayRoot.getResources().getDisplayMetrics().density;

        this.translateSpring = new SpringAnimation(sheetContainer, DynamicAnimation.TRANSLATION_Y, 0f);
        SpringForce force = new SpringForce(0f);
        force.setDampingRatio(0.86f);
        force.setStiffness(420f);
        this.translateSpring.setSpring(force);

        this.translateSpring.addUpdateListener((animation, value, velocity) -> updateChromeForTranslation(value));
        this.translateSpring.addEndListener((animation, canceled, value, velocity) -> {
            if (!canceled && isDismissing) {
                finalizeDismiss();
            }
        });

        scrimView.setOnClickListener(v -> dismiss());
        attachDragGesture(dragHeader, true);
        attachDragGesture(scrollView, false);
    }

    public boolean isShowing() {
        return isShowing;
    }

    public void show() {
        isShowing = true;
        isDismissing = false;
        overlayRoot.setVisibility(View.VISIBLE);
        scrollView.scrollTo(0, 0);

        if (!ValueAnimator.areAnimatorsEnabled()) {
            translateSpring.cancel();
            sheetContainer.setTranslationY(0f);
            sheetContainer.setAlpha(0f);
            scrimView.setAlpha(0f);
            sheetContainer.animate().alpha(1f).setDuration(180).start();
            scrimView.animate().alpha(1f).setDuration(180).start();
            return;
        }

        sheetContainer.setAlpha(1f);
        sheetContainer.post(() -> {
            sheetHeight = Math.max(sheetContainer.getHeight(), 1f);
            if (sheetContainer.getTranslationY() <= 0f || sheetContainer.getTranslationY() >= sheetHeight) {
                sheetContainer.setTranslationY(sheetHeight);
            }
            updateChromeForTranslation(sheetContainer.getTranslationY());
            translateSpring.getSpring().setDampingRatio(0.86f);
            translateSpring.getSpring().setStiffness(420f);
            translateSpring.animateToFinalPosition(0f);
            sheetContainer.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK);
        });
    }

    public void dismiss() {
        dismissWithVelocity(0f);
    }

    private void dismissWithVelocity(float velocityPxPerSec) {
        if (!isShowing) {
            return;
        }
        isDismissing = true;

        if (!ValueAnimator.areAnimatorsEnabled()) {
            translateSpring.cancel();
            sheetContainer.animate().alpha(0f).setDuration(160).withEndAction(this::finalizeDismiss).start();
            scrimView.animate().alpha(0f).setDuration(160).start();
            return;
        }

        sheetHeight = Math.max(sheetContainer.getHeight(), overlayRoot.getHeight() * 0.6f);
        translateSpring.getSpring().setDampingRatio(1.0f);
        translateSpring.getSpring().setStiffness(460f);
        translateSpring.setStartVelocity(Math.max(0f, velocityPxPerSec));
        translateSpring.animateToFinalPosition(sheetHeight + 24f);
    }

    private void finalizeDismiss() {
        isShowing = false;
        isDismissing = false;
        overlayRoot.setVisibility(View.GONE);
        sheetContainer.setTranslationY(0f);
        sheetContainer.setAlpha(1f);
        scrimView.setAlpha(0f);
        resetBackgroundDepth();
    }

    private void updateChromeForTranslation(float translationY) {
        float h = Math.max(sheetHeight, sheetContainer.getHeight());
        if (h <= 0f) {
            return;
        }
        float openFraction = 1f - Math.max(0f, Math.min(1f, translationY / h));
        scrimView.setAlpha(openFraction);
        if (backgroundContent != null && ValueAnimator.areAnimatorsEnabled()) {
            float scale = 1f - (1f - BACKGROUND_MIN_SCALE) * openFraction;
            backgroundContent.setScaleX(scale);
            backgroundContent.setScaleY(scale);
        }
    }

    private void resetBackgroundDepth() {
        if (backgroundContent != null) {
            backgroundContent.setScaleX(1f);
            backgroundContent.setScaleY(1f);
        }
    }

    @SuppressLint("ClickableViewAccessibility")
    private void attachDragGesture(View target, boolean alwaysDrag) {
        target.setOnTouchListener((v, event) -> {
            if (!isShowing) {
                return false;
            }
            switch (event.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    sheetHeight = Math.max(sheetContainer.getHeight(), 1f);
                    downRawY = event.getRawY();
                    startTranslationY = sheetContainer.getTranslationY();
                    dragging = false;
                    dragAllowedFromScroll = alwaysDrag || scrollView.getScrollY() <= 0;
                    if (alwaysDrag) {
                        // Interruptible mid-flight immediately on grab (Apple Design §3)
                        translateSpring.cancel();
                        isDismissing = false;
                    }
                    if (velocityTracker == null) {
                        velocityTracker = VelocityTracker.obtain();
                    } else {
                        velocityTracker.clear();
                    }
                    velocityTracker.addMovement(obtainRawEvent(event));
                    return alwaysDrag;

                case MotionEvent.ACTION_MOVE: {
                    if (velocityTracker != null) {
                        velocityTracker.addMovement(obtainRawEvent(event));
                    }
                    float dy = event.getRawY() - downRawY;
                    if (!dragging) {
                        if (alwaysDrag && Math.abs(dy) > touchSlopPx) {
                            dragging = true;
                            translateSpring.cancel();
                            isDismissing = false;
                        } else if (!alwaysDrag && dragAllowedFromScroll && dy > touchSlopPx) {
                            dragging = true;
                            downRawY = event.getRawY();
                            startTranslationY = sheetContainer.getTranslationY();
                            translateSpring.cancel();
                            isDismissing = false;
                        }
                    }
                    if (dragging) {
                        float rawTarget = startTranslationY + (event.getRawY() - downRawY);
                        float applied;
                        if (rawTarget < 0f) {
                            // Apple Design §9: progressive rubber-band resistance past top bound
                            applied = -rubberband(-rawTarget, sheetHeight);
                        } else {
                            applied = rawTarget;
                        }
                        sheetContainer.setTranslationY(applied);
                        updateChromeForTranslation(applied);
                        return true;
                    }
                    return false;
                }

                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_CANCEL: {
                    float velocityY = 0f;
                    if (velocityTracker != null) {
                        velocityTracker.addMovement(obtainRawEvent(event));
                        velocityTracker.computeCurrentVelocity(1000);
                        velocityY = velocityTracker.getYVelocity();
                        velocityTracker.recycle();
                        velocityTracker = null;
                    }
                    if (dragging || alwaysDrag) {
                        boolean wasDragging = dragging;
                        dragging = false;
                        float currentY = sheetContainer.getTranslationY();
                        // Apple Design §6: exponential momentum projection
                        float projectedY = currentY + project(velocityY);
                        boolean shouldDismiss = wasDragging
                                && (projectedY > sheetHeight * 0.34f || velocityY > 1400f)
                                && velocityY > -350f;
                        if (shouldDismiss) {
                            dismissWithVelocity(velocityY);
                        } else {
                            isDismissing = false;
                            translateSpring.getSpring().setDampingRatio(0.84f);
                            translateSpring.getSpring().setStiffness(420f);
                            translateSpring.setStartVelocity(velocityY);
                            translateSpring.animateToFinalPosition(0f);
                        }
                        return wasDragging;
                    }
                    return false;
                }

                default:
                    return false;
            }
        });
    }

    private static MotionEvent obtainRawEvent(MotionEvent source) {
        MotionEvent copy = MotionEvent.obtain(source);
        copy.setLocation(source.getRawX(), source.getRawY());
        return copy;
    }

    private static float project(float initialVelocityPxPerSec) {
        return (initialVelocityPxPerSec / 1000f) * DECELERATION_RATE / (1f - DECELERATION_RATE);
    }

    private static float rubberband(float overshoot, float dimension) {
        return (overshoot * dimension * RUBBERBAND_CONSTANT)
                / (dimension + RUBBERBAND_CONSTANT * Math.abs(overshoot));
    }

    public void setMaxSheetHeight(int maxHeightPx) {
        ViewGroup.LayoutParams lp = sheetContainer.getLayoutParams();
        if (lp != null && maxHeightPx > 0) {
            lp.height = ViewGroup.LayoutParams.WRAP_CONTENT;
            sheetContainer.setLayoutParams(lp);
            if (sheetContainer instanceof ViewGroup) {
                scrollView.setLayoutParams(new android.widget.LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT));
            }
        }
    }
}
