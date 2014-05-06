/*
 * Copyright (c) 2014 xipki.org
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

package org.xipki.security.shell;

import java.util.Arrays;
import java.util.List;

import org.apache.karaf.shell.console.OsgiCommandSupport;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.xipki.security.api.SecurityFactory;

abstract class KeyGenCommand extends OsgiCommandSupport
{
    private static final ASN1ObjectIdentifier id_pkix = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");
    private static final ASN1ObjectIdentifier id_kp                  = id_pkix.branch("3");
    public static final ASN1ObjectIdentifier id_kp_serverAuth        = id_kp.branch("1");
    public static final ASN1ObjectIdentifier id_kp_clientAuth        = id_kp.branch("2");

    protected abstract String getCertType();

    protected SecurityFactory securityFactory;

    public SecurityFactory getSecurityFactory()
    {
        return securityFactory;
    }

    public void setSecurityFactory(SecurityFactory securityFactory)
    {
        this.securityFactory = securityFactory;
    }

    protected Integer getKeyUsage()
    throws Exception
    {
        String certType =getCertType();
        if(null == certType)
        {
            return null;
        }
        else if("TLS".equalsIgnoreCase(certType) || "TLS-C".equalsIgnoreCase(certType) || "TLS-S".equalsIgnoreCase(certType))
        {
            return KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
        }
        else
        {
            throw new Exception("Unknown certType " + certType);
        }
    }

    protected List<ASN1ObjectIdentifier> getExtendedKeyUsage()
    throws Exception
    {
        String certType = getCertType();
        if(null == certType)
        {
            return null;
        }
        else if("TLS".equalsIgnoreCase(certType))
        {
            return Arrays.asList(id_kp_clientAuth, id_kp_serverAuth);
        }
        else if("TLS-C".equalsIgnoreCase(certType))
        {
            return Arrays.asList(id_kp_clientAuth);
        }
        else if("TLS-S".equalsIgnoreCase(certType))
        {
            return Arrays.asList(id_kp_serverAuth);
        }
        else
        {
            throw new Exception("Unknown certType " + certType);
        }
    }
}
