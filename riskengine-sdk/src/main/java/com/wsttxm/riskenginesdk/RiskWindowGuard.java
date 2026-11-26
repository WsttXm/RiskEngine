package com.wsttxm.riskenginesdk;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.os.Build;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;

import com.wsttxm.riskenginesdk.util.CLog;

/**
 * Optional host-opt-in active window hardening helper.
 *
 * <p>Never invoked automatically by {@link RiskEngine}; hosts call these methods explicitly
 * on sensitive Activities (e.g. login, PIN entry, payment confirmation) to enable
 * {@code FLAG_SECURE}, API 31+ non-system overlay hiding, and tapjacking touch filtering.
 */
public final class RiskWindowGuard {
    private RiskWindowGuard() {}

    /**
     * Toggles {@link WindowManager.LayoutParams#FLAG_SECURE} on the Activity window to block
     * screenshots, screen recordings, and non-secure display projection.
     */
    public static void enableScreenCaptureProtection(Activity activity, boolean enable) {
        if (activity == null) {
            return;
        }
        try {
            Window window = activity.getWindow();
            if (window == null) {
                return;
            }
            if (enable) {
                window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
            } else {
                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
            }
        } catch (Exception | LinkageError e) {
            CLog.w("RiskWindowGuard.enableScreenCaptureProtection failed: " + e.getMessage());
        }
    }

    /**
     * Toggles API 31+ {@link Window#setHideOverlayWindows(boolean)} to suppress non-system
     * overlay windows while the sensitive Activity is visible. Requires the host app to declare
     * {@code android.permission.HIDE_OVERLAY_WINDOWS} if desired; fails safely when absent.
     */
    @SuppressLint("MissingPermission")
    public static void enableOverlayProtection(Activity activity, boolean enable) {
        if (activity == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return;
        }
        try {
            Window window = activity.getWindow();
            if (window == null) {
                return;
            }
            window.setHideOverlayWindows(enable);
        } catch (SecurityException | LinkageError e) {
            CLog.w("RiskWindowGuard.enableOverlayProtection unavailable: " + e.getMessage());
        } catch (Exception e) {
            CLog.w("RiskWindowGuard.enableOverlayProtection failed: " + e.getMessage());
        }
    }

    /**
     * Toggles {@link View#setFilterTouchesWhenObscured(boolean)} on a root or sensitive button
     * view to mitigate tapjacking attacks.
     */
    public static void enableTouchObscuredFilter(View rootView, boolean enable) {
        if (rootView == null) {
            return;
        }
        try {
            rootView.setFilterTouchesWhenObscured(enable);
        } catch (Exception | LinkageError e) {
            CLog.w("RiskWindowGuard.enableTouchObscuredFilter failed: " + e.getMessage());
        }
    }
}
