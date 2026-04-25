package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.AdbInspector;

public class AdbStateCollector extends BaseCollector {

    public AdbStateCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "adb_state";
    }

    @Override
    protected void collect(CollectorResult result) {
        AdbInspector.Snapshot snapshot = AdbInspector.collect(context);
        result.addValue("summary", snapshot.getSummary());
        if (snapshot.getTcpPort() > 0) {
            result.addValue("tcp_port", String.valueOf(snapshot.getTcpPort()));
        }
        if (!snapshot.getDetails().isEmpty()) {
            result.addValue("signals", String.join(",", snapshot.getDetails()));
        }
    }
}
