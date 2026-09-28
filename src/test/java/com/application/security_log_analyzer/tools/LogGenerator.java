package com.application.security_log_analyzer.tools;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.Random;

public class LogGenerator {

    private static final String URL = System.getProperty("url","http://localhost:8081/api/logs");
    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .build();
    private static final Random RANDOM = new Random();

    private static final List<String> USERS = List.of("rohith","arul","abinanth","akilan","harsan");
    private static final List<String> FILES = List.of(
            "/home/rohith/notes.txt","/var/log/app.log","/etc/shadow",
            "finance/payroll.xlsx","/home/bob/report.pdf");
    private static final String RISKY_IP = "198.51.100.66";

    public static void main(String[] args) throws Exception{
        int rounds = args.length > 0 ? Integer.parseInt(args[0]) :5;

        for(int i = 1;i <= rounds;i++){
            System.out.println("---round" + i + "---");
            normalTraffic(8);
            fileAccess();
            if(i % 2==0){
                bruteForceBurst("203.0.113." + (10 + RANDOM.nextInt(50)),pick(USERS));
            }
            if(i==rounds){
                bruteForceBurst(RISKY_IP,"admin");
            }
            Thread.sleep(1000);
        }
        System.out.println("Done.");
    }

    private static void normalTraffic(int count) throws Exception{
        for(int i = 0;i < count;i++){
            String ip = "10.0.0." + (1+RANDOM.nextInt(20));
            String type = RANDOM.nextInt(10) == 0? "LOGIN_FAILURE" : "LOGIN_SUCCESS";
            send(ip,pick(USERS),type,"{\"userAgent\":\"Mozilla/5.0\"}");
            Thread.sleep(100);
        }
    }

    private static void fileAccess() throws Exception{
        for(int i = 0; i < 3;i++){
            String file = pick(FILES);
            send("10.0.0." + (1 + RANDOM.nextInt(20)),pick(USERS),"FILE_ACCESS","{\"path\":\"" + file+ "\"}");
        }
    }

    private static void bruteForceBurst(String ip,String username) throws Exception {
        System.out.println("Brute-force-burst: " + ip + " -> "  + username);
        for(int i = 0;i < 8;i++){
            send(ip,username,"LOGIN_FAILURE","{\"userAgent\":\"hydra\"}");
            Thread.sleep(150);
        }
    }

    private static void send(String ip,String username,String eventType,String metaJson) throws Exception{
        String body = """
                {"timestamp":"%s","ip":"%s","username":"%s","eventType":"%s","meta":%s}
                """.formatted(Instant.now(),ip,username,eventType,metaJson);


        HttpRequest request = HttpRequest.newBuilder(URI.create(URL))
                .header("Content-Type","application/json")
                .header("X-Log-Source","generator")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = CLIENT.send(request,HttpResponse.BodyHandlers.ofString());
        System.out.printf("%d %-13s %-15s %s%n",response.statusCode(),eventType,ip,username);
        if(response.statusCode() != 202){
            System.out.println("  ->" + response.body());
        }
    }

    private static String pick(List<String> items){
        return items.get(RANDOM.nextInt(items.size()));
    }
}
