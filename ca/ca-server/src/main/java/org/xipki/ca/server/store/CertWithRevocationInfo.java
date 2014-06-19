/*
 * Copyright (c) 2014 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server.store;

import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.security.common.CertRevocationInfo;

/**
 * @author Lijun Liao
 */

public class CertWithRevocationInfo
{
    private X509CertificateWithMetaInfo cert;
    private CertRevocationInfo revInfo;

    public CertWithRevocationInfo(X509CertificateWithMetaInfo cert, CertRevocationInfo revInfo)
    {
        this.cert = cert;
        this.revInfo = revInfo;
    }

    public X509CertificateWithMetaInfo getCert()
    {
        return cert;
    }

    public boolean isRevoked()
    {
        return revInfo != null;
    }

    public CertRevocationInfo getRevInfo()
    {
        return revInfo;
    }

    public void setCert(X509CertificateWithMetaInfo cert)
    {
        this.cert = cert;
    }

    public void setRevInfo(CertRevocationInfo revInfo)
    {
        this.revInfo = revInfo;
    }

}
