package com.wsttxm.riskenginesdk.transport;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.wsttxm.riskenginesdk.model.RiskReport;

public class ReportSerializer {
    private final Gson gson;

    public ReportSerializer() {
        gson = new GsonBuilder()
                .disableHtmlEscaping()
                .create();
    }

    public String serialize(RiskReport report) {
        return gson.toJson(report);
    }

    public RiskReport deserialize(String json) {
        return gson.fromJson(json, RiskReport.class);
    }
}
