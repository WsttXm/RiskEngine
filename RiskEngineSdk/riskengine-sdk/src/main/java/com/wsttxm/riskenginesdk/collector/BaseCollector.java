package com.wsttxm.riskenginesdk.collector;

import android.content.Context;

import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.concurrent.Callable;

public abstract class BaseCollector implements Callable<CollectorResult> {
    protected final Context context;

    public BaseCollector(Context context) {
        this.context = context;
    }

    public abstract String getName();

    protected abstract void collect(CollectorResult result);

    @Override
    public CollectorResult call() {
        CollectorResult result = new CollectorResult(getName());
        try {
            collect(result);
        } catch (Exception e) {
            CLog.e("Collector [" + getName() + "] failed", e);
        }
        return result;
    }
}
