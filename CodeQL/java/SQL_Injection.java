import java.sql.*;

public class SQL_Injection {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java App <username>");
            return;
        }

        String userInput = args[0];
        String query = "SELECT * FROM users WHERE username='" + userInput + "'";

        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydatabase", "myuser", "mypassword");
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);

            while (rs.next()) {
                System.out.println(rs.getString("username") + ": " + rs.getString("email"));
            }

            rs.close();
            stmt.close();
            conn.close();
        } catch (SQLException e) {
            System.out.println("SQL error: " + e.getMessage());
        }
    }
}