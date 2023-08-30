package com.company;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;

public class AESFrame extends JFrame implements ActionListener {

    private JTextField keyField, inputField, outputField;
    private JButton randomKeyButton, saveKeyButton, searchInputButton, searchOutputButton, cryptoButton, decryptoButton;
    private JLabel justinfoLabel, infoLabel;

    public AESFrame() {
        //===FRAME====

        setVisible(true);                               //закрытие и видимость
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());
        setMinimumSize(new Dimension(640, 180)); // Устанавливаем минимальный размер окна
        setLocationRelativeTo(null); // Центрируем окно на экране
        setResizable(false);            //запрещаем изменять размер окна

        setTitle("Jaba_AES128");                         //название и иконочка с лягушечкой
        ImageIcon img = new ImageIcon("img/frogico.png");
        setIconImage(img.getImage());

        JPanel mainPanel = new JPanel();        //основная JPanel
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        mainPanel.setSize(460, 30);
        mainPanel.setLayout(new GridBagLayout());
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        add(mainPanel, BorderLayout.NORTH);

        //===KEY====

        JPanel keyPanel = new JPanel();             //keyPanel
        keyPanel.setSize(460, 30);

        JLabel keyText = new JLabel("KEY (128bit)");        //текст
        keyText.setPreferredSize(new Dimension(70, 30));
        keyPanel.add(keyText);

        keyField = new JTextField();            //поле
        keyField.setPreferredSize(new Dimension(300, 30));
        Font fieldFont = new Font("Arial", 0, 15);
        keyField.setFont(fieldFont);
        keyPanel.add(keyField);

        //кнопки
        randomKeyButton = new JButton("Random key");        //рандом
        randomKeyButton.addActionListener(this);
        randomKeyButton.setPreferredSize(new Dimension(130, 30)); // Задаем размер кнопки в пикселях
        keyPanel.add(randomKeyButton);

        saveKeyButton = new JButton("Save key");            //сохранить ключ
        saveKeyButton.addActionListener(this);
        saveKeyButton.setPreferredSize(new Dimension(100, 30)); // Задаем размер кнопки в пикселях
        keyPanel.add(saveKeyButton);

        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        mainPanel.add(keyPanel, gridBagConstraints);

        //INPUT FILE

        JPanel inputPanel = new JPanel();
        inputPanel.setSize(460, 30);

        JLabel inputText = new JLabel("Input: ");        //текст
        inputText.setPreferredSize(new Dimension(60, 30));
        inputPanel.add(inputText);

        inputField = new JTextField();            //поле
        inputField.setPreferredSize(new Dimension(400, 30));
        inputField.setFont(fieldFont);
        inputPanel.add(inputField);

        searchInputButton = new JButton("Search");        //рандом
        searchInputButton.addActionListener(this);
        searchInputButton.setPreferredSize(new Dimension(140, 30)); // Задаем размер кнопки в пикселях
        inputPanel.add(searchInputButton);

        gridBagConstraints.gridy = 1;
        mainPanel.add(inputPanel, gridBagConstraints);

        //OUTPUT DIR

        JPanel outputPanel = new JPanel();
        outputPanel.setSize(460, 30);

        JLabel outputText = new JLabel("Output: ");        //текст
        outputText.setPreferredSize(new Dimension(60, 30));
        outputPanel.add(outputText);

        outputField = new JTextField();            //поле
        outputField.setPreferredSize(new Dimension(400, 30));
        outputField.setFont(fieldFont);
        outputPanel.add(outputField);

        searchOutputButton = new JButton("Search");        //рандом
        searchOutputButton.addActionListener(this);
        searchOutputButton.setPreferredSize(new Dimension(140, 30)); // Задаем размер кнопки в пикселях
        outputPanel.add(searchOutputButton);

        gridBagConstraints.gridy = 2;
        mainPanel.add(outputPanel, gridBagConstraints);

        //CRYPTO/DECRYPTO and info

        JPanel lastPanel = new JPanel();
        lastPanel.setSize(460, 30);

        JLabel byLabel = new JLabel("by Stupin Alexey ");
        byLabel.setPreferredSize(new Dimension(100, 30));
        lastPanel.add(byLabel);

        cryptoButton = new JButton("ENCRYPTO");
        cryptoButton.addActionListener(this);
        cryptoButton.setPreferredSize(new Dimension(100, 30)); // Задаем размер кнопки в пикселях
        lastPanel.add(cryptoButton);

        decryptoButton = new JButton("DECRYPTO");
        decryptoButton.addActionListener(this);
        decryptoButton.setPreferredSize(new Dimension(100, 30)); // Задаем размер кнопки в пикселях
        lastPanel.add(decryptoButton);

        justinfoLabel = new JLabel("info: ");
        justinfoLabel.setFont(fieldFont);
        justinfoLabel.setPreferredSize(new Dimension(50, 30));
        lastPanel.add(justinfoLabel);

        infoLabel = new JLabel();
        infoLabel.setFont(fieldFont);
        infoLabel.setPreferredSize(new Dimension(250, 30));
        lastPanel.add(infoLabel);

        gridBagConstraints.gridy = 3;
        mainPanel.add(lastPanel, gridBagConstraints);

        pack();
    }

    public void actionPerformed(ActionEvent e) {            //события для кнопок

        if (e.getSource() == randomKeyButton) {     //рандом
            String key = generateRandomKey();
            keyField.setText(key);
        } else if (e.getSource() == saveKeyButton) {      //сохранение ключа
            // Сохраняем ключ в файл
            String key = keyField.getText();
            if (isKey(key))
                saveKeyToFile(key);
            else {
                infoLabel.setForeground(Color.RED);
                infoLabel.setText("Key is uncorrect");
            }

        } else if (e.getSource() == searchInputButton) {        //путь инпута
            JFileChooser fileChooser = new JFileChooser();
            int userSelection = fileChooser.showOpenDialog(this);
            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                inputField.setText(selectedFile.getAbsolutePath());
            }
        } else if (e.getSource() == searchOutputButton) {           //путь оутпута
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int userSelection = fileChooser.showSaveDialog(this);
            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File selectedDirectory = fileChooser.getSelectedFile();
                outputField.setText(selectedDirectory.getAbsolutePath());
            }
        } else if (e.getSource() == decryptoButton || e.getSource() == cryptoButton) {
            String key = keyField.getText();
            String inputPath = inputField.getText();
            String outputPath = outputField.getText();
            if (!isKey(key)) {
                infoLabel.setForeground(Color.RED);
                infoLabel.setText("Key is uncorrect");

            } else if (outputField.getText().equals("") || inputField.getText().equals("")) {
                infoLabel.setForeground(Color.RED);
                infoLabel.setText("Input/Output is not entered");
            } else {
                infoLabel.setForeground(Color.BLUE);
                if (e.getSource() == cryptoButton) {
                    try {
                        Cryptor.encrypto(inputPath, outputPath, key);                 //crypto
                        infoLabel.setText("Encrypto was successful");
                        //new First64Bytes(inputPath, outputFilePath);
                    } catch (Exception exception) {
                        infoLabel.setText("Something was wrong :/");
                    }
                } else {
                    try {
                        Cryptor.decrypto(inputPath, outputPath, key);             //decrypto
                        infoLabel.setText("Decrypto was successful");
                    } catch (Exception exception) {
                        infoLabel.setText("Something was wrong :/");
                    }
                }
            }
        }
    }

    private String generateRandomKey() {                   //метод генерации случайного ключа
        String characters = "abcdef0123456789";
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            int index = (int) (Math.random() * characters.length());
            key.append(characters.charAt(index));
        }
        return key.toString();
    }

    private void saveKeyToFile(String key) {               //метод сохранения ключа
        infoLabel.setForeground(Color.BLUE);
        infoLabel.setText("Key is saved");
        JFileChooser fileChooser = new JFileChooser();
        int userSelection = fileChooser.showSaveDialog(this);
        if (userSelection == JFileChooser.APPROVE_OPTION) {         //если выбор файла прошел успешно
            File fileToSave = fileChooser.getSelectedFile();
            try (PrintWriter writer = new PrintWriter(fileToSave)) {
                writer.println(key);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    private boolean isKey(String key)           //проверка корректности ключа
    {
        String hexAlphabet = "abcdef0123456789";
        char[] charHexAlphabet = hexAlphabet.toCharArray();
        char[] charKey = key.toCharArray();

        if (key.length() != 32)
            return false;

        boolean flag;
        for (char element : charKey) {
            flag = false;
            for (char element2 : charHexAlphabet) {
                if (element == element2)
                    flag = true;
            }
            if (!flag)
                return false;
        }

        return true;
    }

}
