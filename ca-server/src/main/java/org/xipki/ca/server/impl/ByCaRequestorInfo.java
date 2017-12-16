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

package org.xipki.ca.server.impl;

import org.xipki.ca.api.InsuffientPermissionException;
import org.xipki.ca.api.NameId;
import org.xipki.ca.server.mgmt.api.RequestorInfo;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class ByCaRequestorInfo implements RequestorInfo {

    private final NameId ident;

    public ByCaRequestorInfo(final NameId ident) {
        this.ident = ParamUtil.requireNonNull("ident", ident);
    }

    @Override
    public NameId ident() {
        return ident;
    }

    @Override
    public boolean isRa() {
        return false;
    }

    @Override
    public boolean isCertProfilePermitted(String certprofile) {
        return true;
    }

    @Override
    public boolean isPermitted(int requiredPermission) {
        return true;
    }

    @Override
    public void assertCertProfilePermitted(String certprofile)
            throws InsuffientPermissionException {
    }

    @Override
    public void assertPermitted(int requiredPermission)
            throws InsuffientPermissionException {
    }

}
