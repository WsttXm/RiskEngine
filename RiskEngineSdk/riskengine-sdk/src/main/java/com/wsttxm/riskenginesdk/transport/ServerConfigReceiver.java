package com.wsttxm.riskenginesdk.transport;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.wsttxm.riskenginesdk.util.CLog;

public class ServerConfigReceiver {

    public interface ConfigUpdateListener {
        void onConfigUpdate(ServerConfig config);
    }

    private ConfigUpdateListener listener;
    private final Gson gson = new Gson();

    public void setListener(ConfigUpdateListener listener) {
        this.listener = listener;
    }

    public void processResponse(String responseJson) {
        try {
            JsonObject json = gson.fromJson(responseJson, JsonObject.class);
            if (json == null) return;

            ServerConfig config = new ServerConfig();
            if (json.has("collect_interval")) {
                config.collectIntervalMs = json.get("collect_interval").getAsLong();
            }
            if (json.has("enabled_detectors")) {
                config.enabledDetectors = gson.fromJson(
                        json.get("enabled_detectors"), String[].class);
            }
            if (json.has("kill_switch")) {
                config.killSwitch = json.get("kill_switch").getAsBoolean();
            }

            if (listener != null) {
                listener.onConfigUpdate(config);
            }
        } catch (Exception e) {
            CLog.e("Config parse failed", e);
        }
    }

    public static class ServerConfig {
        public long collectIntervalMs = -1;
        public String[] enabledDetectors;
        public boolean killSwitch = false;
    }
}
