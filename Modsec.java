import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
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

public class Modsec {
    private static Map<String, Integer> patternCount = new HashMap<>();
    public static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");

    public static void main(String[] args) {
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
        return "/var/www/html/web_pro1/modsec_audit-" + formattedDate + ".log";
    }

    // อ่านข้อมูลจากไฟล์บันทึก log และแยกแต่ละรายการ log.
//
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
    public static void parseAndWriteLogInfo(String logEntry, String data) {
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
    // javac -cp .:mysql-connector-j-8.1.0.jar LogParser.java
    // java -cp .:mysql-connector-j-8.1.0.jar LogParser
    public static void parseLogTypeC(String[] lines, String data) {
        if (lines.length < 3) {
            System.out.println("Invalid log entry structure for Log Type C. Skipping.");
            return;
        }
        String jdbcUrl = "jdbc:mysql://localhost:3306/PROJECT";
        String username = "root";
        String password = "Cs210245"; // แทนที่ด้วยรหัสผ่าน MySQL ของคุณ

        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        // Create a map to store patterns and their counts for the current file

        try {
            String logCData = lines[1].substring(0);
            Class.forName("com.mysql.cj.jdbc.Driver");
            connection = DriverManager.getConnection(jdbcUrl, username, password);

            String sqlQuery = "SELECT md5, namePattern FROM pattern";
            preparedStatement = connection.prepareStatement(sqlQuery);
            resultSet = preparedStatement.executeQuery();
            System.out.println("" + logCData);

            String decodedLogData = urlDecode(logCData);
            // String decodedLogData2 = urlDecode(logCData);
            // System.out.println("test"+decodedLogData);
            String extractedData = extractDataFromLog(decodedLogData);

            // extractedData = extractedData.replace("\n", "");

            // Replace "Login" with an empty string
            extractedData = extractedData.replace("Login", "");

            // Replace "password" with an empty string
            extractedData = extractedData.replace("password", "");
            extractedData = extractedData.trim();
            String[] partsC = decodedLogData.split("&");
            int threshold = 10;
            String status = "";

            while (resultSet.next()) {
                String md5Pattern = resultSet.getString("md5");
                if (md5Pattern.length() >= 7) {
                    String md5php_sub = md5Pattern.substring(0, 7);
                  //  System.err.println("md5sub: " + md5php_sub);
                  String namePattern = resultSet.getString("namePattern");


                if (extractedData != null) {
                    for (String part : partsC) {
                        if (part.startsWith("login=")) {
                            part = part.replace("login=", "");
                            part = part.trim();
                            String hashlogin = hashWithMD5(part);
                            String md5hash_hashlogin = hashlogin.substring(0, 7);
                            if (md5hash_hashlogin.equals(md5php_sub)) {
                                System.out.println("Pattern Detected!!");
                                System.out.println("md5login :" + md5hash_hashlogin);
                                System.out.println("md5php :" + md5php_sub);
                                updatePatternCount(namePattern);
                                for (Map.Entry<String, Integer> entry : patternCount.entrySet()) {
                                    if (part.equals(entry.getKey())) {
                                        System.out
                                                .println("Pattern: " + entry.getKey() + " Count: " + entry.getValue());

                                        // Compare individual values against the threshold
                                        if (entry.getValue() > threshold) {
                                            status += "Red";
                                        } else if (entry.getValue() >= (threshold / 2) - 1) {
                                            status += "Orange";
                                        } else if (entry.getValue() >= (threshold / 5)
                                                || entry.getValue() >= (threshold / 10)) {
                                            status += "Green";
                                        } else {
                                            status += "Check";
                                        }

                                        // Set other parts of your code related to entry within this block
                                        String insertSql = "INSERT INTO detec_history (Patterns, Count, Status, Date_detec) VALUES (?, ?, ?, ?)";

                                        try (PreparedStatement preparedStatement2 = connection
                                                .prepareStatement(insertSql)) {
                                            preparedStatement2.setString(1, entry.getKey());
                                            preparedStatement2.setInt(2, entry.getValue());
                                            preparedStatement2.setString(3, status);

                                            Date currentDate = new Date();
                                            SimpleDateFormat dateFor = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                                            String dateToInsert = dateFor.format(currentDate);
                                            preparedStatement2.setString(4, dateToInsert);

                                            int rowsAffected = preparedStatement2.executeUpdate();

                                            if (rowsAffected > 0) {
                                                System.out.println("Insert successful");
                                            } else {
                                                System.out.println("Insert failed");
                                            }
                                        } catch (SQLException e) {
                                            e.printStackTrace();
                                        }
                                    }

                                }
                            }

                        }
                        if (part.startsWith("password=")) {
                            part = part.replace("password=", "");
                            part = part.trim();
                            String hashpassword = hashWithMD5(part);
                            String md5hash_hashpassword = hashpassword.substring(0, 7);
                            if (md5hash_hashpassword.equals(md5php_sub)) {
                                System.out.println("Pattern Detected!!");
                                System.out.println("md5password :" + md5hash_hashpassword);
                                System.out.println("md5php :" + md5php_sub);
                                updatePatternCount(namePattern);
                                for (Map.Entry<String, Integer> entry : patternCount.entrySet()) {
                                    if (part.equals(entry.getKey())) {
                                        System.out
                                                .println("Pattern: " + entry.getKey() + " Count: " + entry.getValue());

                                        // Compare individual values against the threshold
                                        if (entry.getValue() > threshold) {
                                            status += "Red";
                                        } else if (entry.getValue() >= (threshold / 2) - 1) {
                                            status += "Orange";
                                        } else if (entry.getValue() >= (threshold / 5)
                                                || entry.getValue() >= (threshold / 10)) {
                                            status += "Green";
                                        } else {
                                            status += "Check";
                                        }

                                        // Set other parts of your code related to entry within this block
                                        String insertSql = "INSERT INTO detec_history (Patterns, Count, Status, Date_detec) VALUES (?, ?, ?, ?)";

                                        try (PreparedStatement preparedStatement2 = connection
                                                .prepareStatement(insertSql)) {
                                            preparedStatement2.setString(1, entry.getKey());
                                            preparedStatement2.setInt(2, entry.getValue());
                                            preparedStatement2.setString(3, status);

                                            Date currentDate = new Date();
                                            SimpleDateFormat dateFor = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                                            String dateToInsert = dateFor.format(currentDate);
                                            preparedStatement2.setString(4, dateToInsert);

                                            int rowsAffected = preparedStatement2.executeUpdate();

                                            if (rowsAffected > 0) {
                                                System.out.println("Insert successful");
                                            } else {
                                                System.out.println("Insert failed");
                                            }
                                        } catch (SQLException e) {
                                            e.printStackTrace();
                                        }
                                    }

                                }
                            }

                        }
                        if (part.startsWith("security_level=")) {
                            part = part.replace("security_level=", "");
                            part = part.trim();
                            String hashsecur = hashWithMD5(part);
                            String md5hash_secur = hashsecur.substring(0, 7);
                            if (md5hash_secur.equals(md5php_sub)) {
                                System.out.println("Pattern Detected!!");
                                System.out.println("md5password :" + md5hash_secur);
                                System.out.println("md5php :" + md5php_sub);
                                updatePatternCount(namePattern);
                                for (Map.Entry<String, Integer> entry : patternCount.entrySet()) {
                                    if (part.equals(entry.getKey())) {
                                        System.out
                                                .println("Pattern: " + entry.getKey() + " Count: " + entry.getValue());

                                        // Compare individual values against the threshold
                                        if (entry.getValue() > threshold) {
                                            status += "Red";
                                        } else if (entry.getValue() >= (threshold / 2) - 1) {
                                            status += "Orange";
                                        } else if (entry.getValue() >= (threshold / 5)
                                                || entry.getValue() >= (threshold / 10)) {
                                            status += "Green";
                                        } else {
                                            status += "Check";
                                        }

                                        // Set other parts of your code related to entry within this block
                                        String insertSql = "INSERT INTO detec_history (Patterns, Count, Status, Date_detec) VALUES (?, ?, ?, ?)";

                                        try (PreparedStatement preparedStatement2 = connection
                                                .prepareStatement(insertSql)) {
                                            preparedStatement2.setString(1, entry.getKey());
                                            preparedStatement2.setInt(2, entry.getValue());
                                            preparedStatement2.setString(3, status);

                                            Date currentDate = new Date();
                                            SimpleDateFormat dateFor = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                                            String dateToInsert = dateFor.format(currentDate);
                                            preparedStatement2.setString(4, dateToInsert);

                                            int rowsAffected = preparedStatement2.executeUpdate();

                                            if (rowsAffected > 0) {
                                                System.out.println("Insert successful");
                                            } else {
                                                System.out.println("Insert failed");
                                            }
                                        } catch (SQLException e) {
                                            e.printStackTrace();
                                        }
                                    }

                                }
                            }

                        }
                        if (part.startsWith("form=")) {
                            part = part.replace("form=", "");
                            part = part.trim();
                            String hashform = hashWithMD5(part);
                            String md5hash_form = hashform.substring(0, 7);
                            if (md5hash_form.equals(md5php_sub)) {
                                System.out.println("Pattern Detected!!");
                                System.out.println("md5password :" + md5hash_form);
                                System.out.println("md5php :" + md5php_sub);
                                updatePatternCount(namePattern);
                                for (Map.Entry<String, Integer> entry : patternCount.entrySet()) {
                                    if (part.equals(entry.getKey())) {
                                        System.out
                                                .println("Pattern: " + entry.getKey() + " Count: " + entry.getValue());

                                        // Compare individual values against the threshold
                                        if (entry.getValue() > threshold) {
                                            status += "Red";
                                        } else if (entry.getValue() >= (threshold / 2) - 1) {
                                            status += "Orange";
                                        } else if (entry.getValue() >= (threshold / 5)
                                                || entry.getValue() >= (threshold / 10)) {
                                            status += "Green";
                                        } else {
                                            status += "Check";
                                        }

                                        // Set other parts of your code related to entry within this block
                                        String insertSql = "INSERT INTO detec_history (Patterns, Count, Status, Date_detec) VALUES (?, ?, ?, ?)";

                                        try (PreparedStatement preparedStatement2 = connection
                                                .prepareStatement(insertSql)) {
                                            preparedStatement2.setString(1, entry.getKey());
                                            preparedStatement2.setInt(2, entry.getValue());
                                            preparedStatement2.setString(3, status);

                                            Date currentDate = new Date();
                                            SimpleDateFormat dateFor = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                                            String dateToInsert = dateFor.format(currentDate);
                                            preparedStatement2.setString(4, dateToInsert);

                                            int rowsAffected = preparedStatement2.executeUpdate();

                                            if (rowsAffected > 0) {
                                                System.out.println("Insert successful");
                                            } else {
                                                System.out.println("Insert failed");
                                            }
                                        } catch (SQLException e) {
                                            e.printStackTrace();
                                        }
                                    }

                                }
                            }

                        }
                    }
                }

            }else{
                //System.err.println("MD5 = null");
            }
        }

            // Display the pattern counts for the current file

            System.out.println();
        } catch (SQLException | ClassNotFoundException e) {
            System.out.println("error"+e);
        } finally {
            try {
                if (resultSet != null) {
                    resultSet.close();
                }
                if (preparedStatement != null) {
                    preparedStatement.close();
                }
                if (connection != null) {
                    connection.close();
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
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

