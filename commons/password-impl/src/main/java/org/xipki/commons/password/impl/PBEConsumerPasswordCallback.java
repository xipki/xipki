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

import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.password.api.PasswordCallback;
import org.xipki.commons.password.api.PasswordProducer;
import org.xipki.commons.password.api.PasswordResolverException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

// CHECKSTYLE:SKIP
public class PBEConsumerPasswordCallback implements PasswordCallback {

    private String passwordName;
    private int tries = 3;

    private boolean isPasswordValid(
            final char[] password,
            final String testToken) {
        if (StringUtil.isBlank(testToken)) {
            return true;
        }
        try {
            PBEPasswordServiceImpl.doDecryptPassword(password, testToken);
            return true;
        } catch (PasswordResolverException ex) {
            return false;
        }
    }

    @Override
    public char[] getPassword(
            final String prompt,
            final String testToken)
    throws PasswordResolverException {
        if (passwordName == null) {
            throw new PasswordResolverException("please initialize me first");
        }
        try {
            for (int i = 0; i < tries; i++) {
                char[] password;
                try {
                    password = PasswordProducer.takePassword(passwordName);
                } catch (InterruptedException ex) {
                    throw new PasswordResolverException("interrupted");
                }
                if (isPasswordValid(password, testToken)) {
                    return password;
                }
            }
        } finally {
            PasswordProducer.unregisterPasswordConsumer(passwordName);
        }
        throw new PasswordResolverException("Could not get the password after " + tries + " tries");
    }

    @Override
    public void init(
            final String conf)
    throws PasswordResolverException {
        ParamUtil.requireNonBlank("conf", conf);
        ConfPairs pairs = new ConfPairs(conf);
        String str = pairs.getValue("name");
        if (StringUtil.isBlank(str)) {
            throw new PasswordResolverException("name must not be null");
        }
        this.passwordName = str;
        PasswordProducer.registerPasswordConsumer(this.passwordName);

        str = pairs.getValue("tries");
        if (StringUtil.isNotBlank(str)) {
            int intValue = Integer.parseInt(str);
            if (intValue > 0) {
                this.tries = intValue;
            }
        }
    }

}
