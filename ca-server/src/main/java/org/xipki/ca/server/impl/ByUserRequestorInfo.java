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

package org.xipki.ca.server.impl;

import java.util.Set;

import org.xipki.ca.api.InsuffientPermissionException;
import org.xipki.ca.api.NameId;
import org.xipki.ca.server.mgmt.api.CaHasUserEntry;
import org.xipki.ca.server.mgmt.api.PermissionConstants;
import org.xipki.ca.server.mgmt.api.RequestorInfo;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class ByUserRequestorInfo implements RequestorInfo {

    private final NameId ident;

    private final CaHasUserEntry caHasUser;

    public ByUserRequestorInfo(NameId ident, CaHasUserEntry caHasUser) {
        this.ident = ParamUtil.requireNonNull("ident", ident);
        this.caHasUser = ParamUtil.requireNonNull("caHasUser", caHasUser);
    }

    @Override
    public NameId ident() {
        return ident;
    }

    @Override
    public boolean isRa() {
        return false;
    }

    public int userId() {
        return caHasUser.userIdent().id();
    }

    public CaHasUserEntry caHasUser() {
        return caHasUser;
    }

    @Override
    public boolean isCertProfilePermitted(String certprofile) {
        Set<String> profiles = caHasUser.profiles();
        if (CollectionUtil.isEmpty(profiles)) {
            return false;
        }

        return profiles.contains("ALL") || profiles.contains(certprofile.toUpperCase());
    }

    @Override
    public boolean isPermitted(int permission) {
        return PermissionConstants.contains(caHasUser.permission(), permission);
    }

    @Override
    public void assertCertProfilePermitted(String certprofile)
            throws InsuffientPermissionException {
        if (!isCertProfilePermitted(certprofile)) {
            throw new  InsuffientPermissionException(
                    "CertProfile " + certprofile + " is not permitted");
        }
    }

    @Override
    public void assertPermitted(int permission)
            throws InsuffientPermissionException {
        if (!isPermitted(permission)) {
            throw new  InsuffientPermissionException("Permission "
                    + PermissionConstants.getTextForCode(permission) + " is not permitted");
        }
    }

}
