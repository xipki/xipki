/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
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

package org.xipki.commons.security.pkcs11.internal.proxy;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.xipki.commons.pkcs11proxy.common.Asn1P11EntityIdentifier;
import org.xipki.commons.pkcs11proxy.common.Asn1P11Params;
import org.xipki.commons.pkcs11proxy.common.Asn1RSAPkcsPssParams;
import org.xipki.commons.pkcs11proxy.common.Asn1SignTemplate;
import org.xipki.commons.pkcs11proxy.common.P11ProxyConstants;
import org.xipki.commons.security.api.exception.P11TokenException;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11Identity;
import org.xipki.commons.security.api.p11.P11Params;
import org.xipki.commons.security.api.p11.P11RSAPkcsPssParams;
import org.xipki.commons.security.api.p11.P11Slot;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class ProxyP11Identity extends P11Identity {

    ProxyP11Identity(
            final P11Slot slot,
            final P11EntityIdentifier entityId,
            final PublicKey publicKey,
            final X509Certificate[] certificateChain) {
        super(slot, entityId, publicKey, certificateChain);
    }

    @Override
    protected byte[] doSign(
            final long mechanism,
            final P11Params parameters,
            final byte[] content)
    throws P11TokenException {
        Asn1P11EntityIdentifier asn1EntityId = new Asn1P11EntityIdentifier(identityId);
        Asn1P11Params p11Param = null;
        if (parameters instanceof P11RSAPkcsPssParams) {
            p11Param = new Asn1P11Params(
                    new Asn1RSAPkcsPssParams((P11RSAPkcsPssParams) parameters));
        }
        Asn1SignTemplate signTemplate = new Asn1SignTemplate(asn1EntityId, mechanism,
                p11Param, content);
        ASN1Encodable result = ((ProxyP11Slot) slot).getModule().send(P11ProxyConstants.ACTION_sign,
                signTemplate);

        ASN1OctetString octetString;
        try {
            octetString = DEROctetString.getInstance(result);
        } catch (IllegalArgumentException ex) {
            throw new P11TokenException("the returned result is not OCTET STRING");
        }

        return (octetString == null)
                ? null
                : octetString.getOctets();
    }

}
