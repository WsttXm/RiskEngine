package com.wsttxm.riskenginesdk.transport;

import com.wsttxm.riskenginesdk.util.CLog;

import java.io.IOException;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class TransportClient {
    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    private final OkHttpClient client;
    private final String serverUrl;
    private final String appKey;

    public TransportClient(String serverUrl, String appKey) {
        this.serverUrl = serverUrl;
        this.appKey = appKey;
        this.client = new OkHttpClient.Builder()
                .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
                .writeTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
                .readTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
                .build();
    }

    public void sendReport(String payload, boolean encrypted, TransportCallback callback) {
        if (serverUrl == null || serverUrl.isEmpty()) {
            CLog.w("Server URL not configured, skipping report upload");
            return;
        }

        RequestBody body = RequestBody.create(payload, JSON);
        Request request = new Request.Builder()
                .url(serverUrl + "/api/v1/report")
                .addHeader("X-App-Key", appKey != null ? appKey : "")
                .addHeader("X-Encrypted", String.valueOf(encrypted))
                .addHeader("Content-Type", "application/json")
                .post(body)
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                CLog.e("Report upload failed", e);
                if (callback != null) callback.onFailure(e);
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (Response r = response) {
                    if (r.isSuccessful()) {
                        String responseBody = r.body() != null ? r.body().string() : "";
                        if (callback != null) callback.onSuccess(responseBody);
                    } else {
                        if (callback != null) callback.onFailure(
                                new IOException("Server returned " + r.code()));
                    }
                }
            }
        });
    }

    public interface TransportCallback {
        void onSuccess(String response);
        void onFailure(Exception e);
    }
}
