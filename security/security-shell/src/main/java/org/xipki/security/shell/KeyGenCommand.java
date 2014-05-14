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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;

abstract class KeyGenCommand extends SecurityCommand
{
    private static final ASN1ObjectIdentifier id_pkix = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");
    private static final ASN1ObjectIdentifier id_kp                  = id_pkix.branch("3");
    public static final ASN1ObjectIdentifier id_kp_serverAuth        = id_kp.branch("1");
    public static final ASN1ObjectIdentifier id_kp_clientAuth        = id_kp.branch("2");
    public static final ASN1ObjectIdentifier id_kp_emailProtection   = id_kp.branch("3");

    protected Integer getKeyUsage()
    throws Exception
    {
        return KeyUsage.cRLSign |
                KeyUsage.dataEncipherment |
                KeyUsage.digitalSignature |
                KeyUsage.keyAgreement |
                KeyUsage.keyCertSign |
                KeyUsage.keyEncipherment;
    }

    protected List<ASN1ObjectIdentifier> getExtendedKeyUsage()
    throws Exception
    {
        return Arrays.asList(id_kp_clientAuth, id_kp_serverAuth, id_kp_emailProtection);
    }
}
