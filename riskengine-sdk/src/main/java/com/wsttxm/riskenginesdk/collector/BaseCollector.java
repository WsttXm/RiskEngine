package com.wsttxm.riskenginesdk.collector;

import android.content.Context;

import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;

import java.util.concurrent.Callable;

public abstract class BaseCollector implements Callable<CollectorResult> {
    protected final Context context;

    public BaseCollector(Context context) {
        Context application = context == null ? null : context.getApplicationContext();
        this.context = application != null ? application : context;
    }

    public abstract String getName();

    protected abstract void collect(CollectorResult result);

    protected boolean comparesSources() {
        return false;
    }

    @Override
    public CollectorResult call() {
        CollectorResult result = new CollectorResult(getName(), comparesSources());
        try {
            collect(result);
        } catch (Exception | LinkageError e) {
            CLog.e("Collector [" + getName() + "] failed", e);
            result.markError(e);
        }
        result.finish();
        return result;
    }
}
