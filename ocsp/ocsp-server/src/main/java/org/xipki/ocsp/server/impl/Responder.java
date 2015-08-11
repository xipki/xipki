/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.ocsp.server.impl;

import java.util.List;

import org.xipki.common.util.ParamUtil;
import org.xipki.ocsp.api.CertStatusStore;
import org.xipki.ocsp.api.CertprofileOption;

/**
 * @author Lijun Liao
 */

class Responder
{
    private final ResponderOption responderOption;
    private final RequestOption requestOption;
    private final ResponseOption responseOption;
    private final AuditOption auditOption;
    private final CertprofileOption certprofileOption;
    private final ResponderSigner signer;
    private final List<CertStatusStore> stores;

    Responder(
            final ResponderOption responderOption,
            final RequestOption requestOption,
            final ResponseOption responseOption,
            final AuditOption auditOption,
            final CertprofileOption certprofileOption,
            final ResponderSigner signer,
            final List<CertStatusStore> stores)
    {
        ParamUtil.assertNotNull("responderOption", responderOption);
        ParamUtil.assertNotNull("requestOption", requestOption);
        ParamUtil.assertNotNull("responseOption", responseOption);
        ParamUtil.assertNotNull("signer", signer);
        ParamUtil.assertNotEmpty("stores", stores);

        this.responderOption = responderOption;
        this.requestOption = requestOption;
        this.responseOption = responseOption;
        this.auditOption = auditOption;
        this.certprofileOption = certprofileOption;
        this.signer = signer;
        this.stores = stores;
    }

    public ResponderOption getResponderOption()
    {
        return responderOption;
    }

    public RequestOption getRequestOption()
    {
        return requestOption;
    }

    public ResponseOption getResponseOption()
    {
        return responseOption;
    }

    public AuditOption getAuditOption()
    {
        return auditOption;
    }

    public CertprofileOption getCertprofileOption()
    {
        return certprofileOption;
    }

    public ResponderSigner getSigner()
    {
        return signer;
    }

    public List<CertStatusStore> getStores()
    {
        return stores;
    }

}
