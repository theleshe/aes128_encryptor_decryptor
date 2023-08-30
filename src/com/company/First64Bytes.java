package com.company;

import javax.swing.*;
import java.awt.*;
import java.io.*;

public class First64Bytes extends JFrame {

    private JLabel firstFileLabel;
    private JLabel secondFileLabel;

    public First64Bytes(String pathFirstFile, String pathSecondFile) throws IOException {

        byte[] firstBytes = new byte[64];
        byte[] secondBytes = new byte[64];

        try (FileInputStream firstInputStream = new FileInputStream(pathFirstFile);
             FileInputStream secondInputStream = new FileInputStream(pathSecondFile)) {
            int firstBytesRead = firstInputStream.read(firstBytes);
            int secondBytesRead = secondInputStream.read(secondBytes);

            if (firstBytesRead < 0 || secondBytesRead < 0) {
                throw new IOException("Could not read bytes from both files.");
            }
        }

        setVisible(true);
        setTitle("First 64 bytes");
        setMinimumSize(new Dimension(800, 100)); // Устанавливаем минимальный размер окна
        setLocationRelativeTo(null); // Центрируем окно на экране
        setLayout(new BorderLayout());
        setResizable(false);            //запрещаем изменять размер окна

        JPanel mainPanel = new JPanel();

        mainPanel.setLayout(new GridBagLayout());
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        add(mainPanel, BorderLayout.NORTH);

        JPanel firstPanel = new JPanel();
        firstFileLabel = new JLabel();
        firstFileLabel.setText("Input file: " + bytesToString(firstBytes) + "...");
        firstFileLabel.setPreferredSize(new Dimension(720,30));

        JPanel secondPanel = new JPanel();
        secondFileLabel = new JLabel();
        secondFileLabel.setText("Output file: " + bytesToString(secondBytes) + "...");
        secondFileLabel.setPreferredSize(new Dimension(720,30));

        mainPanel.add(firstFileLabel, gridBagConstraints);
        gridBagConstraints.gridx++;
        mainPanel.add(secondFileLabel, gridBagConstraints);

        pack();
        add(mainPanel);
    }

    private static String bytesToString(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : bytes) {
            stringBuilder.append(String.format("%02X", b));
        }
        return stringBuilder.toString();
    }
}
