package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.util.DisplayMetrics;
import android.view.WindowManager;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;

public class ScreenInfoCollector extends BaseCollector {

    public ScreenInfoCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "screen_info";
    }

    @Override
    protected void collect(CollectorResult result) {
        WindowManager wm = (WindowManager) context.getSystemService(Context.WINDOW_SERVICE);
        if (wm != null) {
            DisplayMetrics dm = new DisplayMetrics();
            wm.getDefaultDisplay().getRealMetrics(dm);
            result.addValue("width", String.valueOf(dm.widthPixels));
            result.addValue("height", String.valueOf(dm.heightPixels));
            result.addValue("density", String.valueOf(dm.density));
            result.addValue("density_dpi", String.valueOf(dm.densityDpi));
            result.addValue("xdpi", String.valueOf(dm.xdpi));
            result.addValue("ydpi", String.valueOf(dm.ydpi));
        }
    }
}
