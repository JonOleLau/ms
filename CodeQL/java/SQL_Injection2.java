import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.sql.*;

public class SQL_Injection2 {
    public static void main(String[] args) {
        // Create a new frame
        JFrame frame = new JFrame("User Search");

        // Create a new panel to hold the components
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Create a new label for the username field
        JLabel lblUsername = new JLabel("Username:");

        // Create a new text field for the username
        JTextField txtUsername = new JTextField(20);

        // Create a new button for searching the users
        JButton btnSearch = new JButton("Search");

        // Create a new text area for the output
        JTextArea outputText = new JTextArea(10, 30);
        outputText.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(outputText);

        // Add an action listener to the search button
        btnSearch.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Get the username from the text field
                String username = txtUsername.getText();

                // Search for the user
                String[] user = searchUsers(username);

                // Check if the user was found
                if (user == null) {
                    JOptionPane.showMessageDialog(panel, "User not found", "Error", JOptionPane.ERROR_MESSAGE);
                } else {
                    outputText.setText("Username: " + user[0] + "\nEmail: " + user[1]);
                }
            }
        });

        // Create a new panel to hold the input fields and search button
        JPanel inputPanel = new JPanel(new GridLayout(2, 2, 10, 10));
        inputPanel.add(lblUsername);
        inputPanel.add(txtUsername);
        inputPanel.add(new JLabel());
        inputPanel.add(btnSearch);

        // Add the input panel and output text area to the main panel
        panel.add(inputPanel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);

        // Set the size of the frame and make it visible
        frame.setSize(350, 250);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setContentPane(panel);
        frame.setVisible(true);

        // Create the database and populate it with sample data
        createDatabase();
    }

    private static void createDatabase() {
        try {
            // Load SQLite JDBC driver
            Class.forName("org.sqlite.JDBC");

            // Connect to a local SQLite database file
            Connection conn = DriverManager.getConnection("jdbc:sqlite:example.db");
            Statement stmt = conn.createStatement();

            // Create users table
            stmt.executeUpdate("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)");

            // Insert sample data
            stmt.executeUpdate("INSERT OR IGNORE INTO users (id, username, email) VALUES (1, 'alice', 'alice@example.com')");
            stmt.executeUpdate("INSERT OR IGNORE INTO users (id, username, email) VALUES (2, 'bob', 'bob@example.com')");
            stmt.executeUpdate("INSERT OR IGNORE INTO users (id, username, email) VALUES (3, 'charlie', 'charlie@example.com')");

            stmt.close();
            conn.close();
        } catch (ClassNotFoundException e) {
            System.out.println("SQLite JDBC driver not found.");
        } catch (SQLException e) {
            System.out.println("SQL error: " + e.getMessage());
        }
    }

    private static String[] searchUsers(String username) {
        String[] user = null;
        try {
            // Load SQLite JDBC driver
            Class.forName("org.sqlite.JDBC");
    
            // Connect to a local SQLite database file
            Connection conn = DriverManager.getConnection("jdbc:sqlite:example.db");
            Statement stmt = conn.createStatement();
    
            // Search for user (with SQL injection vulnerability)
            String query = "SELECT * FROM users WHERE username='" + username + "'";
            ResultSet rs = stmt.executeQuery(query);
    
            if (rs.next()) {
                user = new String[2];
                user[0] = rs.getString("username");
                user[1] = rs.getString("email");
            }
    
            rs.close();
            stmt.close();
            conn.close();
        } catch (ClassNotFoundException e) {
            System.out.println("SQLite JDBC driver not found.");
        } catch (SQLException e) {
            System.out.println("SQL error: " + e.getMessage());
        }
        return user;
    }
    
}