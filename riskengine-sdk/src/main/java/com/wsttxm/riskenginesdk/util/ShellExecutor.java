package com.wsttxm.riskenginesdk.util;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class ShellExecutor {

    public static String execute(String command) {
        StringBuilder output = new StringBuilder();
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", command});
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (output.length() > 0) output.append("\n");
                    output.append(line);
                }
            }
            process.waitFor();
        } catch (Exception e) {
            CLog.e("ShellExecutor failed: " + command, e);
        }
        return output.toString();
    }
}
