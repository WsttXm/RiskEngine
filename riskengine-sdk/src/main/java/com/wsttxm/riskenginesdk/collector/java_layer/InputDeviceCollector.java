package com.wsttxm.riskenginesdk.collector.java_layer;

import android.content.Context;
import android.hardware.input.InputManager;
import android.view.InputDevice;

import com.wsttxm.riskenginesdk.FingerprintHasher;
import com.wsttxm.riskenginesdk.collector.BaseCollector;
import com.wsttxm.riskenginesdk.core.SafeExecutor;
import com.wsttxm.riskenginesdk.model.CollectorResult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Zero-permission collector capturing the sorted input device topology
 * ({@code name}, {@code vendorId}, {@code productId}, {@code sources}, virtual count).
 */
public class InputDeviceCollector extends BaseCollector {

    public static final class InputEntry {
        public final String name;
        public final int vendorId;
        public final int productId;
        public final int sources;
        public final boolean virtualDevice;

        public InputEntry(String name,
                          int vendorId,
                          int productId,
                          int sources,
                          boolean virtualDevice) {
            this.name = name == null ? "" : name.trim();
            this.vendorId = vendorId;
            this.productId = productId;
            this.sources = sources;
            this.virtualDevice = virtualDevice;
        }
    }

    public InputDeviceCollector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "input_devices";
    }

    @Override
    protected void collect(CollectorResult result) {
        if (context == null) {
            result.markUnsupported("context_unavailable");
            return;
        }
        SafeExecutor.SafeResult<List<InputEntry>> safe = SafeExecutor.safeWithTimeoutOrInline(
                SafeExecutor.TIMEOUT_SHORT_MS, () -> readInputDevices(context));
        if (!safe.isSuccess() || safe.getOrNull() == null || safe.getOrNull().isEmpty()) {
            result.markUnsupported("input_manager_unavailable");
            return;
        }
        populateFromEntries(safe.getOrNull(), result);
    }

    /** Deterministic pure-Java population helper shared by runtime collection and JVM tests. */
    public static void populateFromEntries(List<InputEntry> entries, CollectorResult result) {
        if (entries == null || entries.isEmpty()) {
            result.markUnsupported("input_devices_empty");
            return;
        }
        List<String> canonical = new ArrayList<>(entries.size());
        int virtualCount = 0;
        int physicalCount = 0;

        for (InputEntry entry : entries) {
            if (entry == null) {
                continue;
            }
            if (entry.virtualDevice) {
                virtualCount++;
            } else {
                physicalCount++;
            }
            canonical.add(entry.name.toLowerCase(Locale.ROOT)
                    + "|vid=" + entry.vendorId
                    + "|pid=" + entry.productId
                    + "|src=" + Integer.toHexString(entry.sources)
                    + "|virt=" + (entry.virtualDevice ? 1 : 0));
        }
        if (canonical.isEmpty()) {
            result.markUnsupported("input_devices_empty");
            return;
        }
        Collections.sort(canonical);
        result.addValue("input_device_hash",
                FingerprintHasher.sha256Utf8(String.join("\n", canonical)));
        result.addValue("total_count", String.valueOf(canonical.size()));
        result.addValue("virtual_count", String.valueOf(virtualCount));
        result.addValue("physical_count", String.valueOf(physicalCount));
    }

    private static List<InputEntry> readInputDevices(Context ctx) {
        InputManager manager = (InputManager) ctx.getSystemService(Context.INPUT_SERVICE);
        if (manager == null) {
            return Collections.emptyList();
        }
        int[] ids = manager.getInputDeviceIds();
        if (ids == null || ids.length == 0) {
            return Collections.emptyList();
        }
        List<InputEntry> entries = new ArrayList<>(ids.length);
        for (int id : ids) {
            InputDevice device = manager.getInputDevice(id);
            if (device == null) {
                continue;
            }
            entries.add(new InputEntry(
                    device.getName(),
                    device.getVendorId(),
                    device.getProductId(),
                    device.getSources(),
                    device.isVirtual()));
        }
        return entries;
    }
}
