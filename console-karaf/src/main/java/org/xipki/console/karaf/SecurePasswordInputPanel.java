/*
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.console.karaf;

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

class SecurePasswordInputPanel extends Panel
{

    private static final long serialVersionUID = 1L;

    private final JPasswordField passwordField;

    private static final Map<Integer, String[]> keysMap = new HashMap<>();

    static
    {
        int i = 0;
        keysMap.put(i++, new String[]{"1", "2", "3", "4", "5", "6", "7", "8", "9", "0"});
        keysMap.put(i++, new String[]{"!", "@", "§" , "#", "$", "%", "^", "&", "*", "(", ")", "{", "}"});
        keysMap.put(i++, new String[]{"'", "\"", "=", "_", ":", ";", "?", "~", "|", ",", ".", "-", "/"});
        keysMap.put(i++, new String[]{"Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P"});
        keysMap.put(i++, new String[]{"A", "S", "D", "F", "G", "H", "J", "K", "J", "BackSpace"});
        keysMap.put(i++, new String[]{"Shift", "Z", "X", "C", "V", "B", "N", "M", "Clear"});
    }

    private SecurePasswordInputPanel()
    {
        super(new GridLayout(0, 1));

        this.passwordField = new JPasswordField(10);
        passwordField.setEditable(false);

        add(passwordField);

        Set<Integer> rows = new HashSet<>(keysMap.keySet());
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
                JButton button = new JButton(keys[column]);
                button.putClientProperty("key", keys[column].toLowerCase());
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
    private boolean lastKeyShift = false;

    public class MyActionListener implements ActionListener
    {
        @Override
        public void actionPerformed(ActionEvent e)
        {
            JButton btn = (JButton) e.getSource();
            String pressedKey = (String) btn.getClientProperty("key");

            if("shift".equals(pressedKey))
            {
                lastKeyShift = true;
            }
            else
            {
                if("backspace".equals(pressedKey))
                {
                    if(password.length() > 0)
                    {
                        password = password.substring(0, password.length() - 1);
                    }
                }
                else if("clear".equals(pressedKey))
                {
                    password = "";
                }
                else
                {
                    password += lastKeyShift ? pressedKey.toUpperCase() : pressedKey;
                }
                passwordField.setText(password);
                lastKeyShift= false;
            }
        }
    }

    public static void main(String[] args)
    {
        char[] password = readPassword("Enter password");
        System.out.println("'" + new String(password) + "'");
        char[] password2 = readPassword("Enter password");
        System.out.println("'" + new String(password2) + "'");
    }

    static char[] readPassword(String prompt)
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
            String[] options = new String[]{"OK"};
            if(prompt == null || prompt.isEmpty())
            {
                prompt = "Password requried";
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
