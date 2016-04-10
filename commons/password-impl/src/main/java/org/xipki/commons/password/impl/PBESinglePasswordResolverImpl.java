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

package org.xipki.commons.password.impl;

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.password.api.PasswordCallback;
import org.xipki.commons.password.api.PasswordCallbackFactoryRegister;
import org.xipki.commons.password.api.PasswordResolverException;
import org.xipki.commons.password.api.SinglePasswordResolver;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */
// CHECKSTYLE:SKIP
public class PBESinglePasswordResolverImpl implements SinglePasswordResolver {

    private char[] masterPassword;

    private final Object masterPasswordLock = new Object();

    private PasswordCallbackFactoryRegister callbackFactoryRegister;

    private long newPasswordCallbackTimeout = 60000; // 1 minute

    private String masterPasswordCallbackConf;

    private PasswordCallback masterPwdCallback;

    public PBESinglePasswordResolverImpl() {
    }

    protected char[] getMasterPassword(String encryptedPassword)
    throws PasswordResolverException {
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

        if (masterPasswordCallbackConf == null) {
            return;
        }

        String tmpCallback = masterPasswordCallbackConf.trim();
        if (StringUtil.isBlank(tmpCallback)) {
            return;
        }

        String type;
        String conf = null;

        int delimIndex = tmpCallback.indexOf(' ');
        if (delimIndex == -1) {
            type = tmpCallback;
        } else {
            type = tmpCallback.substring(0, delimIndex);
            conf = tmpCallback.substring(delimIndex + 1);
        }

        PasswordCallback pwdCallback;
        try {
            pwdCallback = callbackFactoryRegister.newPasswordCallback(type,
                    newPasswordCallbackTimeout);
            pwdCallback.init(conf);
        } catch (PasswordResolverException ex) {
            throw new IllegalArgumentException("invalid masterPasswordCallback configuration "
                    + tmpCallback + ", " + ex.getClass().getName() + ": " + ex.getMessage());
        }
        this.masterPwdCallback = pwdCallback;
    }

    public void clearMasterPassword() {
        masterPassword = null;
    }

    @Override
    public boolean canResolveProtocol(
            final String protocol) {
        return "PBE".equalsIgnoreCase(protocol);
    }

    @Override
    public char[] resolvePassword(
            final String passwordHint)
    throws PasswordResolverException {
        return PBEPasswordServiceImpl.doDecryptPassword(getMasterPassword(passwordHint),
                passwordHint);
    }

    public void setCallbackFactoryRegister(
            final PasswordCallbackFactoryRegister callbackFactoryRegister) {
        this.callbackFactoryRegister = callbackFactoryRegister;
    }

    public void setMasterPasswordCallback(
            final String masterPasswordCallback) {
        this.masterPasswordCallbackConf = masterPasswordCallback;
    }

    public void setNewPasswordCallbackTimeout(
            final long timeout) {
        this.newPasswordCallbackTimeout = ParamUtil.requireMin("timeout", timeout, 0);
    }

}
