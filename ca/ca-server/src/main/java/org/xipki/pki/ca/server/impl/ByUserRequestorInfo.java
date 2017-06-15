/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.pki.ca.server.impl;

import java.util.Set;

import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.pki.ca.api.InsuffientPermissionException;
import org.xipki.pki.ca.api.NameId;
import org.xipki.pki.ca.server.mgmt.api.CaHasUserEntry;
import org.xipki.pki.ca.server.mgmt.api.PermissionConstants;
import org.xipki.pki.ca.server.mgmt.api.RequestorInfo;

/**
 * @author Lijun Liao
 * @since 2.2.0
 */

public class ByUserRequestorInfo implements RequestorInfo {

    private final NameId ident;

    private final CaHasUserEntry caHasUser;

    public ByUserRequestorInfo(final NameId ident, final CaHasUserEntry caHasUser) {
        this.ident = ParamUtil.requireNonNull("ident", ident);
        this.caHasUser = ParamUtil.requireNonNull("caHasUser", caHasUser);
    }

    @Override
    public NameId getIdent() {
        return ident;
    }

    @Override
    public boolean isRa() {
        return false;
    }

    public int getUserId() {
        return caHasUser.getUserIdent().getId();
    }

    public CaHasUserEntry getCaHasUser() {
        return caHasUser;
    }

    @Override
    public boolean isCertProfilePermitted(String certprofile) {
        Set<String> profiles = caHasUser.getProfiles();
        if (CollectionUtil.isEmpty(profiles)) {
            return false;
        }

        return profiles.contains("ALL") || profiles.contains(certprofile.toUpperCase());
    }

    @Override
    public boolean isPermitted(int permission) {
        return PermissionConstants.contains(caHasUser.getPermission(), permission);
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
