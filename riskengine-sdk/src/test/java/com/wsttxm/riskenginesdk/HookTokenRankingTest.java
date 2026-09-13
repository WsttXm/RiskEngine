package com.wsttxm.riskenginesdk;

import com.wsttxm.riskenginesdk.core.HookEvidenceClassifier;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class HookTokenRankingTest {
    @Test
    public void inlineHookIsStrongAndGmainIsIgnored() {
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("inline_hook:openat"));
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("got_hook:connect"));
        assertEquals(HookEvidenceClassifier.Rank.IGNORE,
                HookEvidenceClassifier.rank("thread:gmain"));
        assertEquals(HookEvidenceClassifier.Rank.WEAK,
                HookEvidenceClassifier.rank("frida_port_open:27042"));
        assertEquals(HookEvidenceClassifier.Rank.IGNORE,
                HookEvidenceClassifier.rank("art_native_flag:invoke"));
        assertEquals(HookEvidenceClassifier.Rank.IGNORE,
                HookEvidenceClassifier.rank("loader_depth:2"));
        assertEquals(HookEvidenceClassifier.Rank.IGNORE,
                HookEvidenceClassifier.rank("passes:2746"));
        assertEquals(HookEvidenceClassifier.Rank.STRONG,
                HookEvidenceClassifier.rank("late_text_mismatch"));
    }
}
