package com.wsttxm.riskenginesdk.demo.ui;

import android.animation.ValueAnimator;
import android.annotation.SuppressLint;
import android.view.HapticFeedbackConstants;
import android.view.MotionEvent;
import android.view.View;

import androidx.dynamicanimation.animation.DynamicAnimation;
import androidx.dynamicanimation.animation.SpringAnimation;
import androidx.dynamicanimation.animation.SpringForce;

/**
 * Apple Design §1 & §10: Instant pointer-down tactile response with critically damped
 * spring physics, ~12dp hit-slop hysteresis for drag-away cancel, and optional haptics.
 */
public final class SpringTouchHelper {

    private static final float HYSTERESIS_DP = 12f;

    private SpringTouchHelper() {}

    public static void attach(View view) {
        attach(view, 0.965f, true);
    }

    public static void attachCompact(View view) {
        attach(view, 0.92f, true);
    }

    @SuppressLint("ClickableViewAccessibility")
    public static void attach(View view, float pressedScale, boolean hapticOnDown) {
        final float hysteresisPx = HYSTERESIS_DP * view.getResources().getDisplayMetrics().density;

        final SpringAnimation scaleX = new SpringAnimation(view, DynamicAnimation.SCALE_X, 1f);
        scaleX.setSpring(createForce(1f));
        final SpringAnimation scaleY = new SpringAnimation(view, DynamicAnimation.SCALE_Y, 1f);
        scaleY.setSpring(createForce(1f));

        final boolean[] pressedInside = {false};

        view.setOnTouchListener((v, event) -> {
            if (!v.isEnabled()) {
                return false;
            }
            switch (event.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    pressedInside[0] = true;
                    animateTo(v, scaleX, scaleY, pressedScale);
                    if (hapticOnDown) {
                        v.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK);
                    }
                    break;
                case MotionEvent.ACTION_MOVE: {
                    boolean inside = isWithinHysteresis(v, event.getX(), event.getY(), hysteresisPx);
                    if (inside != pressedInside[0]) {
                        pressedInside[0] = inside;
                        animateTo(v, scaleX, scaleY, inside ? pressedScale : 1f);
                    }
                    break;
                }
                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_CANCEL:
                    pressedInside[0] = false;
                    animateTo(v, scaleX, scaleY, 1f);
                    break;
                default:
                    break;
            }
            return false;
        });
    }

    private static boolean isWithinHysteresis(View v, float x, float y, float slop) {
        return x >= -slop && x <= v.getWidth() + slop
                && y >= -slop && y <= v.getHeight() + slop;
    }

    private static void animateTo(View view, SpringAnimation sx, SpringAnimation sy, float target) {
        if (!ValueAnimator.areAnimatorsEnabled()) {
            view.setScaleX(1f);
            view.setScaleY(1f);
            view.setAlpha(target < 1f ? 0.78f : 1f);
            return;
        }
        view.setAlpha(1f);
        sx.animateToFinalPosition(target);
        sy.animateToFinalPosition(target);
    }

    private static SpringForce createForce(float target) {
        SpringForce force = new SpringForce(target);
        force.setDampingRatio(1.0f); // critically damped, no overshoot
        force.setStiffness(780f); // crisp ~0.25s response
        return force;
    }
}
