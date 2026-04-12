package org.wstt.riskengineserver.dto;

import java.util.List;
import java.util.Map;

/**
 * 设备指纹DTO, 对应SDK端DeviceFingerprint
 */
public class DeviceFingerprintDTO {
    private Map<String, CollectorResultDTO> results;
    private List<String> inconsistentFields;

    public Map<String, CollectorResultDTO> getResults() { return results; }
    public void setResults(Map<String, CollectorResultDTO> results) { this.results = results; }

    public List<String> getInconsistentFields() { return inconsistentFields; }
    public void setInconsistentFields(List<String> inconsistentFields) { this.inconsistentFields = inconsistentFields; }
}
