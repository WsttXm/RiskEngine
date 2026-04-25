package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.ProcfsUtils;

import java.util.List;

public class ContainerSignalCollector extends BaseCollector {

    public ContainerSignalCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "container_signals";
    }

    @Override
    protected void collect(CollectorResult result) {
        List<String> signals = ProcfsUtils.collectContainerSignals(context);
        result.addValue("summary", signals.isEmpty() ? "none" : "present");
        if (!signals.isEmpty()) {
            result.addValue("signals", String.join(",", signals));
        }
    }
}
