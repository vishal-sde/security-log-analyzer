package com.application.security_log_analyzer.tools;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;

public class ScenarioGenerator {

    private static final String URL = System.getProperty("url", "http://localhost:8081/api/logs");
    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .build();

    public static void main(String[] args) throws Exception {
        banner("SCENARIO 1: Normal login traffic");
        send("10.0.0.12", "priya", "LOGIN_SUCCESS", "{\"userAgent\":\"Chrome/128\"}");
        sleep(400);
        send("10.0.0.18", "arjun", "LOGIN_SUCCESS", "{\"userAgent\":\"Firefox/130\"}");
        sleep(400);

        banner("SCENARIO 2: A single failed login (not an attack - just a typo)");
        send("10.0.0.12", "priya", "LOGIN_FAILURE", "{\"userAgent\":\"Chrome/128\"}");
        sleep(400);
        send("10.0.0.12", "priya", "LOGIN_SUCCESS", "{\"userAgent\":\"Chrome/128\"}"); // retried, got it right
        sleep(800);

        banner("SCENARIO 3: Brute-force attack from a single IP");
        String attackerIp = "203.0.113.77";
        for (int i = 1; i <= 7; i++) {
            send(attackerIp, "admin", "LOGIN_FAILURE", "{\"userAgent\":\"hydra\"}");
            System.out.println("  attempt " + i + "/7 failed");
            sleep(200);
        }
        sleep(800);

        banner("SCENARIO 4: ...and the attacker gets in on attempt 8");
        send(attackerIp, "admin", "LOGIN_SUCCESS", "{\"userAgent\":\"hydra\"}");
        System.out.println("  -> brute-force alert will show CRITICAL territory if combined with risky IP");
        sleep(800);

        banner("SCENARIO 5: Known-risky IP probing a different account");
        String riskyIp = "198.51.100.66";
        for (int i = 1; i <= 3; i++) {
            send(riskyIp, "finance_admin", "LOGIN_FAILURE", "{\"userAgent\":\"python-requests\"}");
            sleep(300);
        }
        sleep(800);

        banner("SCENARIO 6: Sensitive file access, post-compromise");
        send(attackerIp, "admin", "FILE_ACCESS", "{\"path\":\"/etc/shadow\"}");
        sleep(300);
        send(attackerIp, "admin", "FILE_ACCESS", "{\"path\":\"finance/payroll.xlsx\"}");
        sleep(800);

        banner("SCENARIO 7: Multiple distinct users from one IP (shared proxy / NAT, or lateral movement)");
        String sharedIp = "10.0.0.99";
        for (String user : new String[]{"priya", "arjun", "rohith", "admin"}) {
            send(sharedIp, user, "LOGIN_SUCCESS", "{\"userAgent\":\"corp-proxy\"}");
            sleep(250);
        }

        banner("DONE — check the dashboard. You should see: 1 brute-force alert, "
                + "1-2 risky-IP alerts, 2 sensitive-file-access alerts.");
    }

    private static void banner(String text) {
        System.out.println();
        System.out.println("=== " + text + " ===");
    }

    private static void sleep(long ms) throws InterruptedException {
        Thread.sleep(ms);
    }

    private static void send(String ip, String username, String eventType, String metaJson) throws Exception {
        String body = """
                {"timestamp":"%s","ip":"%s","username":"%s","eventType":"%s","meta":%s}
                """.formatted(Instant.now(), ip, username, eventType, metaJson);

        HttpRequest request = HttpRequest.newBuilder(URI.create(URL))
                .header("Content-Type", "application/json")
                .header("X-Log-Source", "scenario")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.printf("  %d  %-13s %-15s %s%n", response.statusCode(), eventType, ip, username);
    }
}