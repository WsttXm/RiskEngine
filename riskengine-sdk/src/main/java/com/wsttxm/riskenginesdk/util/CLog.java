package com.wsttxm.riskenginesdk.util;

import android.util.Log;

public class CLog {
    private static final String TAG = "RiskEngine";
    private static boolean enabled = true;

    public static void setEnabled(boolean enabled) {
        CLog.enabled = enabled;
    }

    public static void d(String msg) {
        if (enabled) Log.d(TAG, msg);
    }

    public static void d(String tag, String msg) {
        if (enabled) Log.d(TAG + ":" + tag, msg);
    }

    public static void i(String msg) {
        if (enabled) Log.i(TAG, msg);
    }

    public static void w(String msg) {
        if (enabled) Log.w(TAG, msg);
    }

    public static void e(String msg) {
        if (enabled) Log.e(TAG, msg);
    }

    public static void e(String msg, Throwable t) {
        if (enabled) Log.e(TAG, msg, t);
    }
}
