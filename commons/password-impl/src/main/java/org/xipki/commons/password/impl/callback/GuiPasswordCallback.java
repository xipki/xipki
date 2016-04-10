/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.commons.password.impl.callback;

import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.password.api.PasswordCallback;
import org.xipki.commons.password.api.PasswordResolverException;
import org.xipki.commons.password.api.SecurePasswordInputPanel;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class GuiPasswordCallback implements PasswordCallback {

    private int quorum = 1;

    private int tries = 3;

    protected boolean isPasswordValid(
            final char[] password,
            final String testToken) {
        return true;
    }

    @Override
    public char[] getPassword(
            final String prompt,
            final String testToken)
    throws PasswordResolverException {
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
    public void init(
            final String conf)
    throws PasswordResolverException {
        if (StringUtil.isBlank(conf)) {
            quorum = 1;
            return;
        }

        ConfPairs pairs = new ConfPairs(conf);
        String str = pairs.getValue("quorum");
        quorum = Integer.valueOf(str);
        if (quorum < 1 || quorum > 10) {
            throw new PasswordResolverException("quorum " + quorum + " is not in [1,10]");
        }

        str = pairs.getValue("tries");
        if (StringUtil.isNotBlank(str)) {
            int intValue = Integer.parseInt(str);
            if (intValue > 0) {
                this.tries = intValue;
            }
        }
    }

}
