package com.wsttxm.riskenginesdk.detector;

import android.content.Context;
import android.os.Debug;
import android.provider.Settings;

import com.wsttxm.riskenginesdk.RiskEngine;
import com.wsttxm.riskenginesdk.collector.java_layer.AndroidIdCollector;
import com.wsttxm.riskenginesdk.collector.native_layer.NativeCollectorBridge;
import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.DetectionStatus;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.lang.reflect.Executable;
import java.util.ArrayList;
import java.util.List;

public class MethodIntegrityDetector extends BaseDetector {

    public MethodIntegrityDetector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "method_integrity";
    }

    @Override
    protected DetectionResult detect() {
        List<String> suspicious = new ArrayList<>();

        inspect(suspicious, RiskEngine.class, "collectSync");
        inspect(suspicious, RiskEngine.class, "getReportJson");
        inspect(suspicious, HookFrameworkDetector.class, "detect");
        inspect(suspicious, DebugDetector.class, "detect");
        inspect(suspicious, EmulatorDetector.class, "detect");
        inspect(suspicious, AndroidIdCollector.class, "collectViaSettingsApi",
                com.wsttxm.riskenginesdk.model.CollectorResult.class);
        inspect(suspicious, Debug.class, "isDebuggerConnected");
        inspect(suspicious, Settings.Secure.class, "getString",
                android.content.ContentResolver.class, String.class);

        if (!suspicious.isEmpty()) {
            return result(
                    RiskLevel.HIGH,
                    DetectionStatus.DANGER,
                    10,
                    10,
                    false,
                    suspicious,
                    String.join("; ", suspicious)
            );
        }
        return safe();
    }

    private void inspect(List<String> suspicious,
                         Class<?> owner,
                         String name,
                         Class<?>... parameterTypes) {
        String methodLabel = owner.getName() + "#" + name;
        try {
            Executable executable = owner.getDeclaredMethod(name, parameterTypes);
            String result = NativeCollectorBridge.nativeInspectMethodEntryPoint(executable);
            if (result == null || result.isEmpty()) {
                return;
            }
            if (result.startsWith("suspicious:")) {
                suspicious.add(methodLabel + ":" + result.substring("suspicious:".length()));
                return;
            }
        } catch (NoSuchMethodException e) {
            CLog.e("Method probe missing: " + methodLabel, e);
        } catch (Exception e) {
            CLog.e("Method integrity inspect failed: " + methodLabel, e);
        }
    }
}
