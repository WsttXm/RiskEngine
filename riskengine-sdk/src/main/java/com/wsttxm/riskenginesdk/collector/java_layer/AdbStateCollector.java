package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.AdbInspector;
import com.wsttxm.riskenginesdk.core.SignalSnapshot;

public class AdbStateCollector extends BaseCollector {
    private final SignalSnapshot signals;

    public AdbStateCollector(Context context) {
        this(context, new SignalSnapshot(context));
    }

    public AdbStateCollector(Context context, SignalSnapshot signals) {
        super(context);
        this.signals = signals;
    }

    @Override
    public String getName() {
        return "adb_state";
    }

    @Override
    protected void collect(CollectorResult result) {
        AdbInspector.Snapshot snapshot = AdbInspector.collect(signals);
        result.addValue("summary", snapshot.getSummary());
        result.addValue("checks_completed", snapshot.getChecksSucceeded()
                + "/" + snapshot.getChecksAttempted());
        if (!snapshot.getFailureReasons().isEmpty()) {
            result.addValue("check_failures", String.join(",", snapshot.getFailureReasons()));
        }
        if (snapshot.getTcpPort() > 0) {
            result.addValue("tcp_port", String.valueOf(snapshot.getTcpPort()));
        }
        if (!snapshot.getDetails().isEmpty()) {
            result.addValue("signals", String.join(",", snapshot.getDetails()));
        }
    }
}
