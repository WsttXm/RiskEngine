package com.wsttxm.riskenginesdk.collector.java_layer;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.telephony.TelephonyManager;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;

public class TelephonyCollector extends BaseCollector {

    public TelephonyCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "telephony";
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void collect(CollectorResult result) {
        if (context.checkSelfPermission(Manifest.permission.READ_PHONE_STATE)
                != PackageManager.PERMISSION_GRANTED) {
            result.addValue("status", "permission_denied");
            return;
        }

        try {
            TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm != null) {
                result.addValue("network_operator", tm.getNetworkOperator());
                result.addValue("network_operator_name", tm.getNetworkOperatorName());
                result.addValue("sim_operator", tm.getSimOperator());
                result.addValue("sim_operator_name", tm.getSimOperatorName());
                result.addValue("sim_state", String.valueOf(tm.getSimState()));
                result.addValue("phone_type", String.valueOf(tm.getPhoneType()));
                result.addValue("network_type", String.valueOf(tm.getDataNetworkType()));

                try {
                    result.addValue("imei", tm.getImei());
                } catch (SecurityException e) {
                    result.addValue("imei", "restricted");
                }
                try {
                    result.addValue("subscriber_id", tm.getSubscriberId());
                } catch (SecurityException e) {
                    result.addValue("subscriber_id", "restricted");
                }
            }
        } catch (Exception e) {
            CLog.e("Telephony failed", e);
        }
    }
}
