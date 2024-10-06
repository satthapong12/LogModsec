import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.text.SimpleDateFormat;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;

//@SuppressWarnings("unused")
public class LogModsec3 {
    private static Map<String, Integer> patternCount = new HashMap<>();
    public static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd-HH");

    public static void main(String[] args) {
        long startTime = System.nanoTime();

        parseLogFile();
        // generateLogFilePath();

        long endTime = System.nanoTime();
        long duration = endTime - startTime;

        System.out.println("Time taken by funtion: " + duration + "nanoseconds");

        long durationInMillis = duration / 1000000;
        System.out.println("Time taken by funtion: " + durationInMillis + "milliseconds");

        double durationInSeconds = (double) duration / 1000000000.0;
        System.out.println("Time taken by function: " + durationInSeconds + "seconds");

    }

    public static void parseLogFile() {
        String filePath = generateLogFilePath();

        // test conn = new test(namePattern);
        // System.out.println("Starting LogParser with file: " + filePath);

        try {
            String[] logEntries = readLogFile(filePath);

            for (String logEntry : logEntries) {

                parseAndWriteLogInfo(logEntry, extractDataFromLog(logEntry));
                // totalCount += count;
            }

        } catch (IOException e) {
            System.out.println("No File data");
        }
    }

    // เพื่อสร้างที่อยู่ของไฟล์บันทึก log และเรียก readLogFile()
    // เพื่ออ่านข้อมูลจากไฟล์บันทึก
    // จากนั้นใช้ parseAndWriteLogInfo() เพื่อวิเคราะห์และแสดงข้อมูล.
    public static String generateLogFilePath() {
        Date currentDate = new Date();

        String formattedDate = dateFormat.format(currentDate);
        System.out.println("Date" + formattedDate);
        return "/var/LogFile/LogAccess/modsec_audit-" + formattedDate + ".log";
    }

    // อ่านข้อมูลจากไฟล์บันทึก log และแยกแต่ละรายการ log.
    public static String[] readLogFile(String filePath) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            StringBuilder stringBuilder = new StringBuilder();
            String line;
            List<String> logEntries = new ArrayList<>();

            while ((line = reader.readLine()) != null) {
                if (line.matches("--[a-zA-Z0-9]+-(A|C)--") && stringBuilder.length() > 0) {
                    logEntries.add(stringBuilder.toString());
                    stringBuilder.setLength(0);
                }
                stringBuilder.append(line).append("\n");
            }

            if (stringBuilder.length() > 0) {
                logEntries.add(stringBuilder.toString());
            }

            return logEntries.toArray(new String[0]);
        }
    }

    // วิเคราะห์และแสดงข้อมูลที่ถูกแยกแยกมาจาก log.
    public static void parseAndWriteLogInfo(String logEntry, String data) throws IOException {
        String[] lines = logEntry.split("\n");
        char logType = extractLogType(lines[0]);

        switch (logType) {
            case 'A':
                parseLogTypeA(lines);
                break;
            case 'C':
                parseLogTypeC(lines, data);
                break;
            default:
                System.out.println("Unknown log type.");
                break;
        }
    }

    // หาประเภทของ log (A หรือ C).
    public static char extractLogType(String logTypeLine) {
        // System.out.println("Log Type Line: " + logTypeLine);

        if (logTypeLine.contains("-A--")) {
            return 'A';
        } else if (logTypeLine.contains("-C--")) {
            return 'C';
        } else {
            return 'U';
        }
    }

    // นำเสนอข้อมูลที่ถูกแยกมาจาก log ประเภท C
    public static void parseLogTypeA(String[] lines) {
        if (lines.length < 2) {
            System.out.println("Invalid log entry structure for Log Type A. Skipping.");
            return;
        }
        String ipLine = lines[1];
        String ip = extractIP(ipLine);
        String actionAndRequestIdLine = lines[0];
        String actionAndRequestId = extractActionAndRequestId(actionAndRequestIdLine);

        String dateAndTimeLine = lines[1];
        String dateTime = extractDateTime(dateAndTimeLine);

        // System.out.println("Log A:");
        System.out.println("Action: " + actionAndRequestId);
        System.out.println("Date and Time: " + dateTime);
        System.out.println("IP: " + ip);
        // System.out.println();

    }

    // นำเสนอข้อมูลที่ถูกแยกมาจาก log ประเภท C
    // javac -cp
    // javac -cp .:mysql-connector-j-8.1.0.jar LogModsec.java
    // java -cp .:mysql-connector-j-8.1.0.jar LogModsec

    public static void parseLogTypeC(String[] lines, String data) throws IOException {
        if (lines.length < 3) {
            System.out.println("Invalid log entry structure for Log Type C. Skipping.");
            return;
        }

        String jdbcUrl = "jdbc:mysql://localhost:3306/pro1_register";
        String username = "root";
        String password = "Cs210245"; // Replace with your MySQL password

        try (Connection connection = DriverManager.getConnection(jdbcUrl, username, password)) {
            Class.forName("com.mysql.cj.jdbc.Driver");

            String logCData = lines[1];
            System.out.println("" + logCData);

            String decodedLogData = urlDecode(logCData);
            String extractedData = extractDataFromLog(decodedLogData).replace("Login", "").replace("password", "")
                    .trim();
            String[] partsC = decodedLogData.split("&");

            Set<String> md5Set = new HashSet<>();
            Map<String, String> patternTypeMap = new HashMap<>();
            Map<String, String> patternNameMap = new HashMap<>();
            Map<String, Integer> thresholdMap = new HashMap<>();

            String dateToInsertToFile = new SimpleDateFormat("yyyy-MM-dd-HH").format(new Date());
            Path fileDetec = Paths.get("/var/LogFile/PatternDetect/fileDetec-" + dateToInsertToFile + ".log");
            String fileString = fileDetec.toString();

            String sqlQuery = "SELECT md5, namePattern, type FROM Pattern";
            try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery);
                    ResultSet resultSet = preparedStatement.executeQuery()) {

                while (resultSet.next()) {
                    String md5Pattern = resultSet.getString("md5");
                    if (md5Pattern.length() >= 32) {
                        String md5php_sub = md5Pattern.substring(0, 32);
                        md5Set.add(md5php_sub);
                        patternTypeMap.put(md5php_sub, resultSet.getString("type"));
                        patternNameMap.put(md5php_sub, resultSet.getString("namePattern"));
                    }
                }
            }

            // Load thresholds from AttackGroup table
            String thresholdQuery = "SELECT name, Threshold FROM AttackGroup";
            try (PreparedStatement thresholdStatement = connection.prepareStatement(thresholdQuery);
                    ResultSet thresholdResultSet = thresholdStatement.executeQuery()) {

                while (thresholdResultSet.next()) {
                    String attackGroup = thresholdResultSet.getString("name");
                    int threshold = thresholdResultSet.getInt("Threshold");
                    thresholdMap.put(attackGroup, threshold);
                }
                System.out.println("checkthresholdMap:" + thresholdMap);
            }

            // Process parts and get total counts by type
            processParts(partsC, extractedData, md5Set, patternTypeMap,
                    patternNameMap, thresholdMap, fileString, connection);

            // Print total counts by type

        } catch (SQLException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    private static Map<String, Integer> processParts(String[] parts, String extractedData, Set<String> md5Set,
            Map<String, String> patternTypeMap, Map<String, String> patternNameMap,
            Map<String, Integer> thresholdMap, String fileDetec, Connection connection)
            throws SQLException, IOException {
        Map<String, Integer> totalCountsByType = new HashMap<>();
        Map<String, Set<String>> detectedPatterns = new HashMap<>();
        Map<String, Set<String>> detectedPatternNames = new HashMap<>();
        String lognull = "d41d8cd98f00b204e9800998ecf8427e";

        for (String part : parts) {
            String cleanedPart = cleanPart(part);
            if (cleanedPart != null) {
                String md5Hash = hashWithMD5(cleanedPart).substring(0, 32);
                if (lognull.contains(md5Hash)) {
                    // Skipping lognull
                } else {
                    if (md5Set.contains(md5Hash)) {
                        System.out.println("Pattern Detected!!");

                        String type = patternTypeMap.get(md5Hash);
                        String patternName = patternNameMap.get(md5Hash);
                        if (type != null) {
                            detectedPatterns.computeIfAbsent(type, k -> new HashSet<>()).add(md5Hash);
                            detectedPatternNames.computeIfAbsent(type, k -> new HashSet<>()).add(patternName);

                            // Increment count for the type
                            totalCountsByType.put(type, totalCountsByType.getOrDefault(type, 0) + 1);
                        }
                    }
                }
            }
        }

        // Aggregate counts and update database
        for (Map.Entry<String, Integer> entry : totalCountsByType.entrySet()) {
            String type = entry.getKey();
            int totalCount = entry.getValue(); // Total count for the type

            // Check if the threshold exists for the type
            if (thresholdMap.containsKey(type)) {
                int threshold = thresholdMap.get(type);
                String status = determineStatus(totalCount, threshold);
                System.out.println("Type: " + type + ", Total Count: " + totalCount + ", Threshold: " + threshold
                        + ", Status: " + status);
                Set<String> patternNames = detectedPatternNames.get(type);
                insertDetecHistory(type, totalCount, threshold, fileDetec, connection, patternNames);
            } else {
                // Handle the case where the threshold is not found
                System.out.println("Threshold not found for type: " + type);
            }
        }

        return totalCountsByType; // Return the map with total counts by type
    }

    private static void insertDetecHistory(String type, int totalCount, int threshold, String fileString,
            Connection connection, Set<String> patternNames) throws SQLException, IOException {
        String status = determineStatus(totalCount, threshold);
        String dateToInsert = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        // ตรวจสอบว่ามีรายการนี้อยู่แล้วในชั่วโมงปัจจุบันหรือไม่
        String checkSql = "SELECT id, Count FROM detec_history WHERE type = ? AND date_detec LIKE ? AND file_path = ?";
        try (PreparedStatement checkStmt = connection.prepareStatement(checkSql)) {
            checkStmt.setString(1, type);
            checkStmt.setString(2, dateToInsert.substring(0, 13) + "%"); // ตรวจสอบสำหรับชั่วโมงเดียวกัน
            checkStmt.setString(3, fileString);
            ResultSet rs = checkStmt.executeQuery();

            if (rs.next()) {
                int existingCount = rs.getInt("Count");
                int updatedCount = existingCount + totalCount;
                status = determineStatus(updatedCount, threshold); // คำนวณสถานะใหม่ตามจำนวนที่อัพเดท

                int id = rs.getInt("id");
                String updateSql = "UPDATE detec_history SET Count = ?, Status = ? WHERE id = ?";
                try (PreparedStatement updateStmt = connection.prepareStatement(updateSql)) {
                    updateStmt.setInt(1, updatedCount);
                    updateStmt.setString(2, status);
                    updateStmt.setInt(3, id);

                    int rowsAffected = updateStmt.executeUpdate();
                    if (rowsAffected > 0) {
                        System.out.println("อัพเดทสำเร็จ");
                    } else {
                        System.out.println("อัพเดทไม่สำเร็จ");
                    }
                }
            } else {
                // เพิ่มบันทึกประวัติการตรวจจับใหม่
                String insertSql = "INSERT INTO detec_history (type, Count, status, date_detec, file_path) VALUES (?, ?, ?, ?, ?)";
                try (PreparedStatement insertStmt = connection.prepareStatement(insertSql)) {
                    insertStmt.setString(1, type);
                    insertStmt.setInt(2, totalCount);
                    insertStmt.setString(3, status);
                    insertStmt.setString(4, dateToInsert);
                    insertStmt.setString(5, fileString);

                    int rowsAffected = insertStmt.executeUpdate();
                    if (rowsAffected > 0) {
                        System.out.println("เพิ่มข้อมูลสำเร็จ");
                    } else {
                        System.out.println("เพิ่มข้อมูลไม่สำเร็จ");
                    }
                }
            }
        }

        logDetectionToFile(type, totalCount, status, dateToInsert, fileString, patternNames);
    }

    private static void logDetectionToFile(String type, int totalCount, String status, String dateToInsert,
            String fileString, Set<String> patternNames) {
        Path filePath = Paths.get(fileString);

        try (BufferedWriter writer = Files.newBufferedWriter(filePath, StandardCharsets.UTF_8,
                StandardOpenOption.APPEND, StandardOpenOption.CREATE)) {
            writer.write(dateToInsert);
            writer.newLine();
            writer.write("Type : " + type);
            writer.newLine();
            writer.write("Patterns : " + String.join(", ", patternNames));
            writer.newLine();
        } catch (IOException e) {
            System.err.println("IOException: " + e.getMessage());
        }
    }

    private static String determineStatus(int totalCount, int threshold) {
        if (totalCount > threshold) {
            return "RED";
        } else if (totalCount >= (threshold / 2)) {
            return "ORANGE";
        } else if (totalCount >= (threshold / 5)) {
            return "GREEN";
        } else {
            return "No Status";
        }
    }

    private static String cleanPart(String part) {
        if (part.startsWith("login=")) {
            return part.replace("login=", "").trim();
        } else if (part.startsWith("password=")) {
            return part.replace("password=", "").trim();
        } else if (part.startsWith("security_level=")) {
            return part.replace("security_level=", "").trim();
        } else if (part.startsWith("form=")) {
            return part.replace("form=", "").trim();
        }
        return null;
    }

    private static void updatePatternCount(String pattern) {
        patternCount.put(pattern, patternCount.getOrDefault(pattern, 0) + 1);
    }

    // นำเสนอที่อยู่ IP จาก log.
    public static String extractIP(String ipLine) {
        String[] parts = ipLine.split(" ");

        for (String part : parts) {
            if (part.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                return part;
            }
        }

        return "N/A";
    }

    // นำเสนอวันที่และเวลาจาก log.
    public static String extractDateTime(String dateTimeLine) {
        Pattern pattern = Pattern.compile("\\[(.*?)\\]");
        Matcher matcher = pattern.matcher(dateTimeLine);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "N/A";
    }

    // นำเสนอข้อมูล action และ request ID จาก log.
    public static String extractActionAndRequestId(String actionAndRequestIdLine) {
        Pattern pattern = Pattern.compile("--([A-Za-z0-9-]+)-[A-C]--");
        Matcher matcher = pattern.matcher(actionAndRequestIdLine);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return "N/A";
    }

    // ทำ URL decoding ข้อมูล.
    public static String urlDecode(String data) {
        try {
            // Replace illegal hex characters in the URL (% followed by a non-hex character)
            data = data.replaceAll("%(?![0-9a-fA-F]{2})", "%25");
            // Trim the string to remove leading and trailing spaces
            data = data.trim();
            return URLDecoder.decode(data, "UTF-8");
        } catch (Exception e) {
            System.err.println("Error decoding URL");
            e.printStackTrace();
            return null;
        }
    }

    // แยกข้อมูลที่เกี่ยวข้องกับ login, password, และ form จากข้อมูล log.
    public static String extractDataFromLog(String logData) {
        String loginPattern = "login=([^&]+)";
        String passwordPattern = "password=([^&]+)";
        // String formPattern = "form=([^&]+)";

        Pattern loginP = Pattern.compile(loginPattern);
        Pattern passwordP = Pattern.compile(passwordPattern);
        // Pattern formP = Pattern.compile(formPattern);

        Matcher loginM = loginP.matcher(logData);
        Matcher passwordM = passwordP.matcher(logData);
        // Matcher formM = formP.matcher(logData);

        StringBuilder extractedData = new StringBuilder();

        if (loginM.find()) {
            extractedData.append("Login").append(loginM.group(1)).append("\n");
        }
        if (passwordM.find()) {
            extractedData.append("password").append(passwordM.group(1)).append("\n");
        }
        // if (formM.find()) {
        // extractedData.append("Form Data: ").append(formM.group(1)).append("\n");
        // }
        // System.out.println("testsadas"+extractedData);
        // Return the extracted data or a message if no data found
        return extractedData.length() > 0 ? extractedData.toString() : "No match";

    }

    // ทำการคำนวณ MD5 hash ของข้อมูล.
    public static String hashWithMD5(String data) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(data.getBytes());
            StringBuilder hexString = new StringBuilder();

            for (byte hashByte : hashBytes) {
                String hex = Integer.toHexString(0xff & hashByte);
                if (hex.length() == 1)
                    hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("ไม่พบอัลกอริทึม MD5");
            e.printStackTrace();
            return null;
        }
    }

    // นำเสนอข้อมูลที่ตรงกับรูปแบบที่กำหนด.
    public static String extractDataUsingPattern(String data, String pattern) {
        // Implement extraction logic using the pattern (regex)
        // This is a simple example and you may need to modify it based on your
        // requirements
        // Here, we are using a simple regex match to extract the data
        String result = "Not found";
        String regex = pattern + "=([^&,]+)";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(regex);
        java.util.regex.Matcher m = p.matcher(data);
        if (m.find()) {
            result = m.group(1);
        }
        return result;
    }

}
