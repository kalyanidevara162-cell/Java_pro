import java.io.*;
import java.nio.file.*;
import java.util.*;

public class CyberSecurityLogAnalyzer {

    private static final int ALERT_THRESHOLD = 3;

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        System.out.println("==================================");
        System.out.println(" CYBERSECURITY LOG ANALYZER");
        System.out.println("==================================");

        System.out.print("Enter log file path (security.log): ");
        String fileName = sc.nextLine().trim();

        if (fileName.isEmpty()) {
            fileName = "security.log";
        }

        analyzeLogs(fileName);
        sc.close();
    }

    static void analyzeLogs(String fileName) {
        int total = 0;
        int successful = 0;
        int failed = 0;
        int invalid = 0;

        Map<String, Integer> failedByIP = new HashMap<>();
        Map<String, Integer> failedByUser = new HashMap<>();

        try {
            List<String> lines =
                Files.readAllLines(Paths.get(fileName));

            for (String line : lines) {
                if (line.trim().isEmpty()) {
                    continue;
                }

                String[] data = line.split(",", -1);

                if (data.length != 4) {
                    invalid++;
                    continue;
                }

                String timestamp = data[0].trim();
                String ip = data[1].trim();
                String username = data[2].trim();
                String status = data[3].trim().toUpperCase();

                if (timestamp.isEmpty() || ip.isEmpty()
                        || username.isEmpty()
                        || !(status.equals("SUCCESS")
                        || status.equals("FAILED"))) {
                    invalid++;
                    continue;
                }

                total++;

                if (status.equals("SUCCESS")) {
                    successful++;
                } else {
                    failed++;

                    failedByIP.put(
                        ip, failedByIP.getOrDefault(ip, 0) + 1
                    );

                    failedByUser.put(
                        username,
                        failedByUser.getOrDefault(username, 0) + 1
                    );
                }
            }

            System.out.println("\n========== SECURITY REPORT ==========");
            System.out.println("Total valid logins : " + total);
            System.out.println("Successful logins  : " + successful);
            System.out.println("Failed logins      : " + failed);
            System.out.println("Invalid log entries: " + invalid);

            System.out.println("\n--- Suspicious IP Alerts ---");

            boolean alertFound = false;

            for (Map.Entry<String, Integer> entry
                    : failedByIP.entrySet()) {

                if (entry.getValue() >= ALERT_THRESHOLD) {
                    alertFound = true;

                    System.out.println(
                        "ALERT: IP " + entry.getKey()
                        + " had " + entry.getValue()
                        + " failed login attempts."
                    );
                }
            }

            if (!alertFound) {
                System.out.println("No IP reached the alert threshold.");
            }

            System.out.println("\n--- Users With Repeated Failures ---");

            boolean userAlert = false;

            for (Map.Entry<String, Integer> entry
                    : failedByUser.entrySet()) {

                if (entry.getValue() >= ALERT_THRESHOLD) {
                    userAlert = true;
                    System.out.println(
                        "User: " + entry.getKey()
                        + " | Failed attempts: " + entry.getValue()
                    );
                }
            }

            if (!userAlert) {
                System.out.println("No user reached the alert threshold.");
            }

            saveReport(total, successful, failed, invalid,
                       failedByIP);

        } catch (IOException e) {
            System.out.println("Error reading log file: "
                               + e.getMessage());
            System.out.println(
                "Check that the file exists and is readable."
            );
        }
    }

    static void saveReport(
            int total,
            int successful,
            int failed,
            int invalid,
            Map<String, Integer> failedByIP) {

        try (PrintWriter writer =
                 new PrintWriter("security_report.txt")) {

            writer.println("CYBERSECURITY LOG ANALYSIS REPORT");
            writer.println("--------------------------------");
            writer.println("Total valid logins : " + total);
            writer.println("Successful logins  : " + successful);
            writer.println("Failed logins      : " + failed);
            writer.println("Invalid log entries: " + invalid);

            writer.println("\nSUSPICIOUS IP ADDRESSES:");

            for (Map.Entry<String, Integer> entry
                    : failedByIP.entrySet()) {

                if (entry.getValue() >= ALERT_THRESHOLD) {
                    writer.println(
                        entry.getKey() + " - "
                        + entry.getValue()
                        + " failed attempts"
                    );
                }
            }

            System.out.println(
                "\nReport saved to security_report.txt"
            );

        } catch (IOException e) {
            System.out.println("Could not save report: "
                               + e.getMessage());
        }
    }
}