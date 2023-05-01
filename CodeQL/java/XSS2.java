import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class XSS2 {
    public static void main(String[] args) {
        // Create a new frame
        JFrame frame = new JFrame("XSS Demo");

        // Create a new panel to hold the components
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Create a new label for the message field
        JLabel lblMessage = new JLabel("Message:");

        // Create a new text field for the message
        JTextField txtMessage = new JTextField(20);

        // Create a new button for displaying the message
        JButton btnDisplay = new JButton("Display");

        // Create a JEditorPane to display the message
        JEditorPane editorPane = new JEditorPane();
        editorPane.setEditable(false);
        editorPane.setContentType("text/html");

        // Add an action listener to the display button
        btnDisplay.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Get the message from the text field
                String message = txtMessage.getText();

                // Set the message as the content of the JEditorPane
                editorPane.setText("<html><body>" + message + "</body></html>");
            }
        });

        // Create a new panel to hold the input fields and display button
        JPanel inputPanel = new JPanel(new GridLayout(2, 2, 10, 10));
        inputPanel.add(lblMessage);
        inputPanel.add(txtMessage);
        inputPanel.add(new JLabel());
        inputPanel.add(btnDisplay);

        // Add the input panel and editor pane to the main panel
        panel.add(inputPanel, BorderLayout.NORTH);
        panel.add(new JScrollPane(editorPane), BorderLayout.CENTER);

        // Set the size of the frame and make it visible
        frame.setSize(400, 300);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setContentPane(panel);
        frame.setVisible(true);
    }
}
