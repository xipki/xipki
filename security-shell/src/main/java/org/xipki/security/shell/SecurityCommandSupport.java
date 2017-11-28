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

package org.xipki.security.shell;

import java.util.Date;

import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.xipki.common.util.DateUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.XipkiCommandSupport;
import org.xipki.security.SecurityFactory;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.P11CryptService;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotIdentifier;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class SecurityCommandSupport extends XipkiCommandSupport {

    protected static final String DEFAULT_P11MODULE_NAME =
            P11CryptServiceFactory.DEFAULT_P11MODULE_NAME;

    @Reference
    protected SecurityFactory securityFactory;

    @Reference (optional = true)
    protected P11CryptServiceFactory p11CryptServiceFactory;

    protected P11Slot getSlot(final String moduleName, final int slotIndex)
            throws XiSecurityException, P11TokenException, IllegalCmdParamException {
        P11Module module = getP11Module(moduleName);
        P11SlotIdentifier slotId = module.getSlotIdForIndex(slotIndex);
        return module.getSlot(slotId);
    }

    protected P11Module getP11Module(final String moduleName)
            throws XiSecurityException, P11TokenException, IllegalCmdParamException {
        P11CryptService p11Service = p11CryptServiceFactory.getP11CryptService(moduleName);
        if (p11Service == null) {
            throw new IllegalCmdParamException("undefined module " + moduleName);
        }
        return p11Service.module();
    }

    protected String toUtcTimeyyyyMMddhhmmssZ(final Date date) {
        return DateUtil.toUtcTimeyyyyMMddhhmmss(date) + "Z";
    }

}
