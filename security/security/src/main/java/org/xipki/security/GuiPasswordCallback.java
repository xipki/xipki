/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.security;

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

import org.xipki.security.api.PasswordCallback;
import org.xipki.security.api.PasswordResolverException;

/**
 * @author Lijun Liao
 */

public class GuiPasswordCallback implements PasswordCallback
{

    private final static class SecurePasswordInputPanel extends Panel
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
    }

    @Override
    public char[] getPassword(String prompt)
    throws PasswordResolverException
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
                throw new PasswordResolverException("User has cancelled");
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

    @Override
    public void init(String conf)
    throws PasswordResolverException
    {
    }
}
