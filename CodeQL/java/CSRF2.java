import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class CSRF2 {
    public static void main(String[] args) {
        createMainFrame();
        createAttackerFrame();
    }

    private static void createMainFrame() {
        JFrame mainFrame = new JFrame("Main Site - Bank");
        mainFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        mainFrame.setSize(300, 200);

        JPanel mainPanel = new JPanel(new BorderLayout());
        mainFrame.setContentPane(mainPanel);

        mainPanel.add(new JLabel("Transfer Funds"), BorderLayout.NORTH);

        JPanel formPanel = new JPanel(new GridLayout(3, 2));
        mainPanel.add(formPanel, BorderLayout.CENTER);

        formPanel.add(new JLabel("Amount:"));
        formPanel.add(new JTextField());
        formPanel.add(new JLabel("To Account:"));
        formPanel.add(new JTextField());
        JButton transferButton = new JButton("Transfer");
        formPanel.add(transferButton);

        transferButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JOptionPane.showMessageDialog(mainFrame, "Funds transferred!", "Success", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        mainFrame.setVisible(true);
    }

    private static void createAttackerFrame() {
        JFrame attackerFrame = new JFrame("Attacker Site");
        attackerFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        attackerFrame.setSize(300, 200);

        JPanel attackerPanel = new JPanel(new BorderLayout());
        attackerFrame.setContentPane(attackerPanel);

        attackerPanel.add(new JLabel("Attacker Site"), BorderLayout.NORTH);

        JButton maliciousButton = new JButton("Click me for free stuff!");
        attackerPanel.add(maliciousButton, BorderLayout.CENTER);

        maliciousButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JOptionPane.showMessageDialog(attackerFrame, "You got free stuff!", "Success", JOptionPane.INFORMATION_MESSAGE);
                // Simulate CSRF attack by calling the transfer funds action
                JOptionPane.showMessageDialog(null, "Funds transferred!", "Success", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        attackerFrame.setVisible(true);
    }
}
