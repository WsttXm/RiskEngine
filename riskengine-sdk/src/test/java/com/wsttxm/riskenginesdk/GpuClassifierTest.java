package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.GpuClassifier;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class GpuClassifierTest {
    @Test
    public void hardwareAngleOnStockAndroidDevicesIsNotFlagged() {
        assertNull(GpuClassifier.matchVirtualMarker(
                "Qualcomm", "ANGLE (Qualcomm, Adreno (TM) 750, OpenGL ES 3.2)"));
        assertNull(GpuClassifier.matchVirtualMarker(
                "ARM", "ANGLE (ARM, Mali-G715 Immortalis MC11, OpenGL ES 3.2)"));
        assertNull(GpuClassifier.matchVirtualMarker(
                "Samsung Electronics Co., Ltd.", "ANGLE (Samsung, Xclipse 940, OpenGL ES 3.2)"));
        assertNull(GpuClassifier.matchVirtualMarker("Qualcomm", "Adreno (TM) 660"));
    }

    @Test
    public void virtualAndSoftwareRenderersAreDetected() {
        assertEquals("swiftshader", GpuClassifier.matchVirtualMarker(
                "Google Inc.", "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device), OpenGL ES 3.0)"));
        assertEquals("virgl", GpuClassifier.matchVirtualMarker("Mesa/X.org", "virgl"));
        assertEquals("llvmpipe", GpuClassifier.matchVirtualMarker("Mesa", "llvmpipe (LLVM 15.0)"));
        assertEquals("angle_soft", GpuClassifier.matchVirtualMarker(
                "Google", "ANGLE (Unknown Virtual Adapter, OpenGL ES 3.0)"));
        assertNotNull(GpuClassifier.matchVirtualMarker("VMware, Inc.", "Gallium 0.4 on SVGA3D"));
    }
}
