/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.ConfPairs;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.password.PBEPasswordService;
import org.xipki.password.PasswordProducer;
import org.xipki.password.PasswordResolverException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

// CHECKSTYLE:SKIP
public class PBEConsumerPasswordCallback implements PasswordCallback {

    private static final Logger LOG = LoggerFactory.getLogger(PBEConsumerPasswordCallback.class);
    private String passwordName;
    private int tries = 3;

    private boolean isPasswordValid(final char[] password, final String testToken) {
        if (StringUtil.isBlank(testToken)) {
            return true;
        }
        try {
            PBEPasswordService.decryptPassword(password, testToken);
            return true;
        } catch (PasswordResolverException ex) {
            return false;
        }
    }

    @Override
    public char[] getPassword(final String prompt, final String testToken)
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
                boolean valid = isPasswordValid(password, testToken);
                PasswordProducer.setPasswordCorrect(passwordName, valid);
                if (valid) {
                    return password;
                }
            }
        } finally {
            PasswordProducer.unregisterPasswordConsumer(passwordName);
        }
        String msg = "Could not get the password " + passwordName + "after " + tries + " tries";
        LOG.error(msg);
        System.out.println(msg);
        throw new PasswordResolverException(msg);
    }

    @Override
    public void init(final String conf) throws PasswordResolverException {
        ParamUtil.requireNonBlank("conf", conf);
        ConfPairs pairs = new ConfPairs(conf);
        String str = pairs.value("name");
        if (StringUtil.isBlank(str)) {
            throw new PasswordResolverException("name must not be null");
        }
        this.passwordName = str;
        PasswordProducer.registerPasswordConsumer(this.passwordName);

        str = pairs.value("tries");
        if (StringUtil.isNotBlank(str)) {
            int intValue = Integer.parseInt(str);
            if (intValue > 0) {
                this.tries = intValue;
            }
        }
    }

}
