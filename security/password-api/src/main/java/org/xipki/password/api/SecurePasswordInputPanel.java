/*
 * Copyright (c) 2015 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.password.api;

import java.awt.Color;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Panel;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.LookAndFeel;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

/**
 * @author Lijun Liao
 */

public class SecurePasswordInputPanel extends Panel
{

    private static final long serialVersionUID = 1L;

    private static final String BACKSPACE = "\u21E6";
    private static final String CAPS = "\u21E7";
    private static final String CLEAR = "Clear";
    private static final String OK = "OK";

    private final JPasswordField passwordField;

    private static final Map<Integer, String[]> keysMap = new HashMap<Integer, String[]>();
    private final Set<JButton> buttons = new HashSet<JButton>();

    static
    {
        int i = 0;
        keysMap.put(i++, new String[]{"1", "2", "3", "4", "5", "6", "7", "8", "9", "0"});
        keysMap.put(i++, new String[]{"!", "@", "§" , "#", "$", "%", "^", "&", "*", "(", ")", "{", "}"});
        keysMap.put(i++, new String[]{"'", "\"", "=", "_", ":", ";", "?", "~", "|", ",", ".", "-", "/"});
        keysMap.put(i++, new String[]{"q", "w", "e", "r", "z", "y", "u", "i", "o", "p"});
        keysMap.put(i++, new String[]{"a", "s", "d", "f", "g", "h", "j", "k", "j", BACKSPACE});
        keysMap.put(i++, new String[]{CAPS, "z", "x", "c", "v", "b", "n", "m", CLEAR});
    }

    private SecurePasswordInputPanel()
    {
        super(new GridLayout(0, 1));

        this.passwordField = new JPasswordField(10);
        passwordField.setEditable(false);

        add(passwordField);

        Set<Integer> rows = new HashSet<Integer>(keysMap.keySet());
        int n = rows.size();

        SecureRandom random = new SecureRandom();
        while(rows.isEmpty() == false)
        {
            int row = random.nextInt() % n;
            if(rows.contains(row) == false)
            {
                continue;
            }

            String[] keys = keysMap.get(row);
            rows.remove(row);

            JPanel panel = new JPanel();
            for (int column = 0; column < keys.length; column++)
            {
                String text = keys[column];
                JButton button = new JButton(text);
                button.setFont(button.getFont().deriveFont(Font.TRUETYPE_FONT));
                if(CLEAR.equalsIgnoreCase(text))
                {
                    button.setBackground(Color.red);
                } else if(CAPS.equalsIgnoreCase(text) || BACKSPACE.equalsIgnoreCase(text))
                {
                    button.setBackground(Color.lightGray);
                } else
                {
                    buttons.add(button);
                }

                button.putClientProperty("key", text);
                button.addActionListener(new MyActionListener());
                panel.add(button);
            }
            add(panel);
        }

        //setVisible(true);
    }

    public char[] getPassword()
    {
        return password.toCharArray();
    }

    private String password = "";
    private boolean caps = false;

    public class MyActionListener implements ActionListener
    {
        @Override
        public void actionPerformed(
                final ActionEvent e)
        {
            JButton btn = (JButton) e.getSource();
            String pressedKey = (String) btn.getClientProperty("key");

            if(CAPS.equals(pressedKey))
            {
                for(JButton button : buttons)
                {
                    String text = button.getText();
                    text = caps ? text.toLowerCase() : text.toUpperCase();
                    button.setText(text);
                }
                caps = !caps;
                return;
            }

            if(BACKSPACE.equals(pressedKey))
            {
                if(password.length() > 0)
                {
                    password = password.substring(0, password.length() - 1);
                }
            }
            else if(CLEAR.equals(pressedKey))
            {
                password = "";
            }
            else
            {
                password += btn.getText();
            }
            passwordField.setText(password);
        }
    }

    public static void main(
            final String[] args)
    {
        char[] password = readPassword("Enter password");
        System.out.println("'" + new String(password) + "'");
        char[] password2 = readPassword("Enter password");
        System.out.println("'" + new String(password2) + "'");
    }

    public static char[] readPassword(
            String prompt)
    {
        LookAndFeel currentLookAndFeel = UIManager.getLookAndFeel();
        try
        {
            UIManager.setLookAndFeel(
                UIManager.getSystemLookAndFeelClassName());
        } catch(Exception e)
        {
        }

        try
        {
            SecurePasswordInputPanel gui = new SecurePasswordInputPanel();
            String[] options = new String[]{OK};
            if(prompt == null || prompt.isEmpty())
            {
                prompt = "Password required";
            }

            int option = JOptionPane.showOptionDialog(null, gui, prompt,
                    JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
                    null, options, options[0]);

            if(option == 0) // pressing OK button
            {
                return gui.getPassword();
            }
            else
            {
                return null;
            }
        }finally
        {
            try
            {
                UIManager.setLookAndFeel(currentLookAndFeel);
            } catch (UnsupportedLookAndFeelException e)
            {
            }
        }
    }

}
