package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.core.SignalResult;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

import java.util.List;

public class ContainerSignalCollector extends BaseCollector {
    private final SignalSnapshot signals;

    public ContainerSignalCollector(Context context) {
        this(context, new SignalSnapshot(context));
    }

    public ContainerSignalCollector(Context context, SignalSnapshot signals) {
        super(context);
        this.signals = signals;
    }

    @Override
    public String getName() {
        return "container_signals";
    }

    @Override
    protected void collect(CollectorResult result) {
        SignalResult<List<String>> snapshot = signals.getContainerSignals();
        if (!snapshot.isSuccess() || snapshot.getValue() == null) {
            result.markError(snapshot.getFailureReason());
            return;
        }
        List<String> values = snapshot.getValue();
        result.addValue("summary", values.isEmpty() ? "none" : "present");
        if (!values.isEmpty()) {
            result.addValue("signals", String.join(",", values));
        }
    }
}
