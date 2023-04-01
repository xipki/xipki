// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.password;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Secure panel to enter password.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class SecurePasswordInputPanel extends Panel {

  private static final String BACKSPACE = "⇦"; // double left arrow

  private static final String CAPS = "⇧"; // double upper arrow

  private static final String CLEAR = "Clear";

  private static final String OK = "OK";

  private static final Map<Integer, String[]> KEYS_MAP = new HashMap<>();

  private final JPasswordField passwordField;

  private final Set<JButton> buttons = new HashSet<>();

  private String password = "";
  private boolean caps;

  static {
    int idx = 0;
    KEYS_MAP.put(idx++, new String[]{"1", "2", "3", "4", "5", "6", "7", "8", "9", "0"});
    KEYS_MAP.put(idx++, new String[]{"!", "@", "§", "#", "$", "%", "^", "&", "*", "(", ")", "{", "}"});
    KEYS_MAP.put(idx++, new String[]{"'", "\"", "=", "_", ":", ";", "?", "~", "|", ",", ".", "-", "/"});
    KEYS_MAP.put(idx++, new String[]{"q", "w", "e", "r", "t", "y", "u", "i", "o", "p"});
    KEYS_MAP.put(idx++, new String[]{"a", "s", "d", "f", "g", "h", "j", "k", "l", BACKSPACE});
    KEYS_MAP.put(idx,   new String[] {CAPS, "z", "x", "c", "v", "b", "n", "m", CLEAR});
  } // method static

  private SecurePasswordInputPanel() {
    super(new GridLayout(0, 1));

    this.passwordField = new JPasswordField(10);
    passwordField.setEditable(false);

    add(passwordField);

    Set<Integer> rows = new HashSet<>(KEYS_MAP.keySet());
    final int n = rows.size();

    while (!rows.isEmpty()) {
      int row = Args.nextInt(n);
      if (!rows.contains(row)) {
        continue;
      }

      String[] keys = KEYS_MAP.get(row);
      rows.remove(row);

      JPanel panel = new JPanel();
      for (String text : keys) {
        JButton button = new JButton(text);
        button.setFont(button.getFont().deriveFont(Font.TRUETYPE_FONT));
        if (CLEAR.equalsIgnoreCase(text)) {
          button.setBackground(Color.red);
        } else if (Args.orEqualsIgnoreCase(text, CAPS, BACKSPACE)) {
          button.setBackground(Color.lightGray);
        } else {
          buttons.add(button);
        }

        button.putClientProperty("key", text);
        button.addActionListener(e -> {
          JButton btn = (JButton) e.getSource();
          String pressedKey = (String) btn.getClientProperty("key");

          if (CAPS.equals(pressedKey)) {
            for (JButton m : buttons) {
              String txt = m.getText();
              m.setText(caps ? txt.toLowerCase() : txt.toUpperCase());
            }
            caps = !caps;
            return;
          }

          if (BACKSPACE.equals(pressedKey)) {
            if (password.length() > 0) {
              password = password.substring(0, password.length() - 1);
            }
          } else if (CLEAR.equals(pressedKey)) {
            password = "";
          } else {
            password += btn.getText();
          }
          passwordField.setText(password);

        });
        panel.add(button);
      } // end for
      add(panel);
    } // end while(!rows.isEmpty())

    //setVisible(true);
  } // constructor

  public char[] getPassword() {
    return password.toCharArray();
  }

  public static char[] readPassword(String prompt) {
    LookAndFeel currentLookAndFeel = UIManager.getLookAndFeel();
    try {
      UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
    } catch (Exception ex) {
    }

    try {
      SecurePasswordInputPanel gui = new SecurePasswordInputPanel();
      String[] options = new String[]{OK};

      String tmpPrompt = prompt;
      if (tmpPrompt == null || tmpPrompt.isEmpty()) {
        tmpPrompt = "Password required";
      }

      int option = JOptionPane.showOptionDialog(null, gui, tmpPrompt, JOptionPane.OK_OPTION,
          JOptionPane.PLAIN_MESSAGE, null, options, options[0]);

      if (option == 0) { // pressing OK button
        return gui.getPassword();
      } else {
        return null;
      }
    } finally {
      try {
        UIManager.setLookAndFeel(currentLookAndFeel);
      } catch (UnsupportedLookAndFeelException ex) {
      }
    }
  } // method readPassword

}
