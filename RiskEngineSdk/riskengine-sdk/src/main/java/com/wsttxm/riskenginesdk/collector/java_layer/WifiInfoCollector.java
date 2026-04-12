package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;

import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.model.CollectorResult;
import com.wsttxm.riskenginesdk.util.CLog;

public class WifiInfoCollector extends BaseCollector {

    public WifiInfoCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "wifi_info";
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void collect(CollectorResult result) {
        try {
            WifiManager wm = (WifiManager) context.getApplicationContext()
                    .getSystemService(Context.WIFI_SERVICE);
            if (wm != null) {
                WifiInfo info = wm.getConnectionInfo();
                if (info != null) {
                    result.addValue("mac_address", info.getMacAddress());
                    result.addValue("ssid", info.getSSID());
                    result.addValue("bssid", info.getBSSID());
                    result.addValue("ip_address", intToIp(info.getIpAddress()));
                    result.addValue("link_speed", String.valueOf(info.getLinkSpeed()));
                    result.addValue("rssi", String.valueOf(info.getRssi()));
                }
            }
        } catch (Exception e) {
            CLog.e("WifiInfo failed", e);
        }
    }

    private String intToIp(int i) {
        return (i & 0xFF) + "." + ((i >> 8) & 0xFF) + "." +
                ((i >> 16) & 0xFF) + "." + ((i >> 24) & 0xFF);
    }
}
