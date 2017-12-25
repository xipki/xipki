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

package org.xipki.ca.server.impl.cmp;

import org.xipki.ca.api.InsuffientPermissionException;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.X509CertWithDbId;
import org.xipki.ca.server.mgmt.api.CaHasRequestorEntry;
import org.xipki.ca.server.mgmt.api.PermissionConstants;
import org.xipki.ca.server.mgmt.api.RequestorInfo;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CmpRequestorInfo implements RequestorInfo {

    private final CaHasRequestorEntry caHasRequestor;

    private final X509CertWithDbId cert;

    public CmpRequestorInfo(final CaHasRequestorEntry caHasRequestor, final X509CertWithDbId cert) {
        this.caHasRequestor = ParamUtil.requireNonNull("caHasRequestor", caHasRequestor);
        this.cert = ParamUtil.requireNonNull("cert", cert);
    }

    public CaHasRequestorEntry caHasRequestor() {
        return caHasRequestor;
    }

    public X509CertWithDbId cert() {
        return cert;
    }

    @Override
    public NameId ident() {
        return caHasRequestor.requestorIdent();
    }

    @Override
    public boolean isRa() {
        return caHasRequestor.isRa();
    }

    @Override
    public boolean isCertProfilePermitted(String certprofile) {
        return caHasRequestor.isCertProfilePermitted(certprofile);
    }

    @Override
    public boolean isPermitted(int permission) {
        return caHasRequestor.isPermitted(permission);
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
