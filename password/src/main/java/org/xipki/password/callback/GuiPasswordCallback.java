/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.password.callback;

import org.xipki.common.ConfPairs;
import org.xipki.common.util.StringUtil;
import org.xipki.password.PasswordResolverException;
import org.xipki.password.SecurePasswordInputPanel;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class GuiPasswordCallback implements PasswordCallback {

    private int quorum = 1;

    private int tries = 3;

    protected boolean isPasswordValid(char[] password, String testToken) {
        return true;
    }

    @Override
    public char[] getPassword(String prompt, String testToken) throws PasswordResolverException {
        String tmpPrompt = prompt;
        if (StringUtil.isBlank(tmpPrompt)) {
            tmpPrompt = "Password required";
        }

        for (int i = 0; i < tries; i++) {
            char[] password;
            if (quorum == 1) {
                password = SecurePasswordInputPanel.readPassword(tmpPrompt);
                if (password == null) {
                    throw new PasswordResolverException("user has cancelled");
                }
            } else {
                char[][] passwordParts = new char[quorum][];
                for (int j = 0; j < quorum; j++) {
                    String promptPart = tmpPrompt + " (part " + (j + 1) + "/" + quorum + ")";
                    passwordParts[j] = SecurePasswordInputPanel.readPassword(promptPart);
                    if (passwordParts[j] == null) {
                        throw new PasswordResolverException("user has cancelled");
                    }
                }
                password = StringUtil.merge(passwordParts);
            }

            if (isPasswordValid(password, testToken)) {
                return password;
            }
        }

        throw new PasswordResolverException("Could not get the password after " + tries + " tries");
    }

    @Override
    public void init(String conf) throws PasswordResolverException {
        if (StringUtil.isBlank(conf)) {
            quorum = 1;
            return;
        }

        ConfPairs pairs = new ConfPairs(conf);
        String str = pairs.value("quorum");
        quorum = Integer.valueOf(str);
        if (quorum < 1 || quorum > 10) {
            throw new PasswordResolverException("quorum " + quorum + " is not in [1,10]");
        }

        str = pairs.value("tries");
        if (StringUtil.isNotBlank(str)) {
            int intValue = Integer.parseInt(str);
            if (intValue > 0) {
                this.tries = intValue;
            }
        }
    }

}
