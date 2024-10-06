import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class ShowFilePath {

    public static void main(String[] args) {
        String jdbcUrl = "jdbc:mysql://localhost:3306/pro1_register";
        String username = "root";
        String password = "Cs210245"; // Use the correct password

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            try (Connection connection = DriverManager.getConnection(jdbcUrl, username, password)) {
                // Call the function to display the file path
                displayFilePath(1, connection); // Change 90 to the desired id
            }
        } catch (SQLException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static void displayFilePath(int id, Connection connection) throws SQLException {
        String sqlQuery = "SELECT file_path FROM detec_history WHERE id = ?";
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setInt(1, id); // Set the id parameter

            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                while (resultSet.next()) {
                    String filePath = resultSet.getString("file_path");
                    System.out.println("File Path: " + filePath);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
