package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.model.DevicePosture;

/**
 * Push-mode device security hygiene listener decoupled from active threat alerts.
 */
public interface DeviceStateListener {

    /** Invoked once device posture (lockscreen, encryption, keystore, VPN, store) is evaluated. */
    default void onDeviceStateEvaluated(DevicePosture posture) {}
}
