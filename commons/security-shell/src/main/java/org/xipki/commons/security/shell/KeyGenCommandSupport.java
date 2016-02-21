/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
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

package org.xipki.commons.security.shell;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.commons.security.api.KeyUsage;
import org.xipki.commons.security.api.ObjectIdentifiers;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class KeyGenCommandSupport extends SecurityCommandSupport {
    private static final Set<KeyUsage> DFLT_KEYUSAGE;
    private static final List<ASN1ObjectIdentifier> DFLT_EXT_KEYUSAGE;

    static {
        Set<KeyUsage> usages = new HashSet<>(12);
        usages.add(KeyUsage.cRLSign);
        usages.add(KeyUsage.dataEncipherment);
        usages.add(KeyUsage.digitalSignature);
        usages.add(KeyUsage.keyAgreement);
        usages.add(KeyUsage.keyCertSign);
        usages.add(KeyUsage.keyEncipherment);
        DFLT_KEYUSAGE = Collections.unmodifiableSet(usages);

        List<ASN1ObjectIdentifier> list =
                Arrays.asList(ObjectIdentifiers.id_kp_clientAuth,
                ObjectIdentifiers.id_kp_serverAuth,
                ObjectIdentifiers.id_kp_emailProtection,
                ObjectIdentifiers.id_kp_OCSPSigning);
        DFLT_EXT_KEYUSAGE = Collections.unmodifiableList(list);
    }

    protected Set<KeyUsage> getKeyUsage() {
        return DFLT_KEYUSAGE;
    }

    protected List<ASN1ObjectIdentifier> getExtendedKeyUsage() {
        return DFLT_EXT_KEYUSAGE;
    }

}
