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

package org.xipki.security.shell;

import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.xipki.security.common.ObjectIdentifiers;

/**
 * @author Lijun Liao
 */

abstract class KeyGenCommand extends SecurityCommand
{
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
        return Arrays.asList(ObjectIdentifiers.id_kp_clientAuth,
                ObjectIdentifiers.id_kp_serverAuth,
                ObjectIdentifiers.id_kp_emailProtection,
                ObjectIdentifiers.id_kp_OCSPSigning);
    }
}
