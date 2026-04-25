package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.os.Build;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;

public class BuildPropsCollector extends BaseCollector {

    public BuildPropsCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "build_props";
    }

    @Override
    protected void collect(CollectorResult result) {
        result.addValue("brand", Build.BRAND);
        result.addValue("model", Build.MODEL);
        result.addValue("device", Build.DEVICE);
        result.addValue("product", Build.PRODUCT);
        result.addValue("board", Build.BOARD);
        result.addValue("hardware", Build.HARDWARE);
        result.addValue("manufacturer", Build.MANUFACTURER);
        result.addValue("fingerprint", Build.FINGERPRINT);
        result.addValue("display", Build.DISPLAY);
        result.addValue("host", Build.HOST);
        result.addValue("tags", Build.TAGS);
        result.addValue("type", Build.TYPE);
        result.addValue("user", Build.USER);
        result.addValue("bootloader", Build.BOOTLOADER);
        result.addValue("radio", Build.getRadioVersion());
        result.addValue("sdk_int", String.valueOf(Build.VERSION.SDK_INT));
        result.addValue("release", Build.VERSION.RELEASE);
        result.addValue("incremental", Build.VERSION.INCREMENTAL);
        result.addValue("security_patch", Build.VERSION.SECURITY_PATCH);
    }
}
