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

import org.xipki.common.util.StringUtil;
import org.xipki.password.PBEPasswordService;
import org.xipki.password.PasswordResolverException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

// CHECKSTYLE:SKIP
public class PBEGuiPasswordCallback extends GuiPasswordCallback {

    @Override
    protected boolean isPasswordValid(final char[] password, final String testToken) {
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

}
