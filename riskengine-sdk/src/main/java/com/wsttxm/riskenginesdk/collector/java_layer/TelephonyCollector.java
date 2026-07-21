package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.telephony.TelephonyManager;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;

/** Collects non-sensitive telephony capability data without privileged identifiers. */
public class TelephonyCollector extends BaseCollector {
    public TelephonyCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "telephony";
    }

    @Override
    protected void collect(CollectorResult result) {
        try {
            TelephonyManager manager = (TelephonyManager)
                    context.getSystemService(Context.TELEPHONY_SERVICE);
            if (manager == null) {
                result.markUnsupported("telephony_service_unavailable");
                return;
            }
            result.addValue("phone_type", String.valueOf(manager.getPhoneType()));
            result.addValue("sim_state", String.valueOf(manager.getSimState()));
        } catch (SecurityException e) {
            result.markUnsupported("telephony_permission_restricted");
        } catch (Exception e) {
            CLog.e("Telephony collection failed", e);
            result.markError(e);
        }
    }
}
