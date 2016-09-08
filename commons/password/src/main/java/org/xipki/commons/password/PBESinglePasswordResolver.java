/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.commons.password;

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.password.callback.FilePasswordCallback;
import org.xipki.commons.password.callback.GuiPasswordCallback;
import org.xipki.commons.password.callback.OBFPasswordCallback;
import org.xipki.commons.password.callback.PBEConsumerPasswordCallback;
import org.xipki.commons.password.callback.PBEGuiPasswordCallback;
import org.xipki.commons.password.callback.PasswordCallback;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class PBESinglePasswordResolver implements SinglePasswordResolver {

    private char[] masterPassword;

    private final Object masterPasswordLock = new Object();

    private String masterPasswordCallback = "PBE-GUI";

    private PasswordCallback masterPwdCallback;

    public PBESinglePasswordResolver() {
    }

    protected char[] getMasterPassword(String encryptedPassword) throws PasswordResolverException {
        synchronized (masterPasswordLock) {
            init();
            if (masterPassword == null) {
                if (masterPwdCallback == null) {
                    throw new PasswordResolverException(
                            "masterPasswordCallback is not initialized");
                }
                this.masterPassword = masterPwdCallback.getPassword(
                        "Please enter the master password", encryptedPassword);
            }
            return masterPassword;
        }
    }

    private void init() {
        if (masterPwdCallback != null) {
            return;
        }

        if (StringUtil.isBlank(masterPasswordCallback)) {
            return;
        }

        String type;
        String conf = null;

        int delimIndex = masterPasswordCallback.indexOf(' ');
        if (delimIndex == -1) {
            type = masterPasswordCallback;
        } else {
            type = masterPasswordCallback.substring(0, delimIndex);
            conf = masterPasswordCallback.substring(delimIndex + 1);
        }

        PasswordCallback pwdCallback;
        if ("FILE".equalsIgnoreCase(type)) {
            pwdCallback = new FilePasswordCallback();
        } else if ("GUI".equalsIgnoreCase(type)) {
            pwdCallback = new GuiPasswordCallback();
        } else if ("PBE-GUI".equalsIgnoreCase(type)) {
            pwdCallback = new PBEGuiPasswordCallback();
        } else if ("PBE-Consumer".equalsIgnoreCase(type)) {
            pwdCallback = new PBEConsumerPasswordCallback();
        } else if ("OBF".equalsIgnoreCase(type)) {
            pwdCallback = new OBFPasswordCallback();
            if (!conf.startsWith("OBF:")) {
                conf = "OBF:" + conf;
            }
        } else {
            throw new RuntimeException("unknown PasswordCallback type '" + type + "'");
        }

        try {
            pwdCallback.init(conf);
        } catch (PasswordResolverException ex) {
            throw new IllegalArgumentException("invalid masterPasswordCallback configuration "
                    + masterPasswordCallback + ", " + ex.getClass().getName() + ": "
                    + ex.getMessage());
        }
        this.masterPwdCallback = pwdCallback;
    }

    public void clearMasterPassword() {
        masterPassword = null;
    }

    @Override
    public boolean canResolveProtocol(final String protocol) {
        return "PBE".equalsIgnoreCase(protocol);
    }

    @Override
    public char[] resolvePassword(final String passwordHint) throws PasswordResolverException {
        return PBEPasswordService.decryptPassword(getMasterPassword(passwordHint),
                passwordHint);
    }

    public void setMasterPasswordCallback(final String masterPasswordCallback) {
        this.masterPasswordCallback = ParamUtil.requireNonBlank("masterPasswordCallback",
                masterPasswordCallback).trim();
    }

}
