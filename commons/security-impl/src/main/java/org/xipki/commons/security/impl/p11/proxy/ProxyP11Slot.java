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

package org.xipki.commons.security.impl.p11.proxy;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.xipki.commons.pkcs11proxy.common.ASN1EntityIdentifier;
import org.xipki.commons.pkcs11proxy.common.ASN1KeyIdentifier;
import org.xipki.commons.pkcs11proxy.common.ASN1SlotIdentifier;
import org.xipki.commons.pkcs11proxy.common.P11ProxyConstants;
import org.xipki.commons.security.api.BadAsn1ObjectException;
import org.xipki.commons.security.api.p11.AbstractP11Slot;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11Identity;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11MechanismFilter;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.p11.P11UnknownEntityException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ProxyP11Slot extends AbstractP11Slot {

    ProxyP11Slot(
            final String moduleName,
            final P11SlotIdentifier slotId,
            final P11MechanismFilter mechanismFilter)
    throws P11TokenException {
        super(moduleName, slotId, mechanismFilter);
        refresh();
    }

    @Override
    public void refresh()
    throws P11TokenException {
        ASN1SlotIdentifier asn1SlotId = new ASN1SlotIdentifier(slotId);
        ASN1Encodable resp = getModule().send(P11ProxyConstants.ACTION_getKeyIds, asn1SlotId);
        if (!(resp instanceof ASN1Sequence)) {
            throw new P11TokenException("response is not ASN1Sequence, but "
                    + resp.getClass().getName());
        }

        ASN1Sequence seq = (ASN1Sequence) resp;
        final int n = seq.size();

        List<P11KeyIdentifier> keyIds = new LinkedList<>();
        for (int i = 0; i < n; i++) {
            ASN1KeyIdentifier asn1KeyId;
            try {
                asn1KeyId = ASN1KeyIdentifier.getInstance(seq.getObjectAt(i));
            } catch (BadAsn1ObjectException ex) {
                throw new P11TokenException("invalid response: " + ex.getMessage(), ex);
            }
            P11KeyIdentifier keyId = asn1KeyId.getKeyId();
            keyIds.add(keyId);
        }

        final int size = keyIds.size();
        Set<P11Identity> currentIdentifies = new HashSet<>((int) (size + size / 2));
        for (P11KeyIdentifier keyId : keyIds) {
            P11EntityIdentifier entityId = new P11EntityIdentifier(slotId, keyId);
            X509Certificate[] certs = getCertificates(entityId);
            PublicKey pubKey = null;
            if (certs == null || certs.length == 0) {
                pubKey = getPublicKey(entityId);
            }
            ProxyP11Identity identity = new ProxyP11Identity(moduleName,
                    new P11EntityIdentifier(slotId, keyId), certs, pubKey);
            currentIdentifies.add(identity);
        }
        setIdentities(currentIdentifies);

        // FIXME: setMechanisms
    }

    @Override
    public void close() {
    }

    private PublicKey getPublicKey(
            final P11EntityIdentifier entityId)
    throws P11UnknownEntityException, P11TokenException {
        ASN1Encodable result = getModule().send(P11ProxyConstants.ACTION_getPublicKey,
                new ASN1EntityIdentifier(entityId));

        ASN1OctetString octetString;
        try {
            octetString = DEROctetString.getInstance(result);
        } catch (IllegalArgumentException ex) {
            throw new P11TokenException("the returned result is not OCTETSTRING");
        }

        if (octetString == null) {
            return null;
        }
        return generatePublicKey(octetString.getOctets());
    }

    private X509Certificate[] getCertificates(
            final P11EntityIdentifier entityId)
    throws P11TokenException {
        ASN1Encodable result = getModule().send(P11ProxyConstants.ACTION_getCertificates,
                new ASN1EntityIdentifier(entityId));

        ASN1Sequence seq = ASN1Sequence.getInstance(result);
        final int size = seq.size();
        X509Certificate[] certs = new X509Certificate[size];

        for (int i = 0; i < size; i++) {
            Certificate bcCert = Certificate.getInstance(seq.getObjectAt(i));
            try {
                certs[i] = new X509CertificateObject(bcCert);
            } catch (CertificateParsingException ex) {
                throw new P11TokenException("could not parse certificate at index " + i + ":"
                        + ex.getMessage(), ex);
            }
        }

        return certs;
    }

    private static PublicKey generatePublicKey(
            final byte[] encodedSubjectPublicKeyInfo)
    throws P11TokenException {
        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(
                encodedSubjectPublicKeyInfo);

        X509EncodedKeySpec keyspec = new X509EncodedKeySpec(encodedSubjectPublicKeyInfo);
        ASN1ObjectIdentifier aid = pkInfo.getAlgorithm().getAlgorithm();

        KeyFactory kf;

        try {
            if (PKCSObjectIdentifiers.rsaEncryption.equals(aid)) {
                kf = KeyFactory.getInstance("RSA");
            } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(aid)) {
                kf = KeyFactory.getInstance("ECDSA");
            } else if (X9ObjectIdentifiers.id_dsa.equals(aid)) {
                kf = KeyFactory.getInstance("DSA");
            } else {
                throw new P11TokenException("unsupported key algorithm: " + aid);
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new P11TokenException("NoSuchAlgorithmException: " + ex.getMessage(), ex);
        }

        try {
            return kf.generatePublic(keyspec);
        } catch (InvalidKeySpecException ex) {
            throw new P11TokenException("InvalidKeySpecException: " + ex.getMessage(), ex);
        }
    }

    private ProxyP11Module getModule()
    throws P11TokenException {
        ProxyP11Module module = ProxyP11ModulePool.getInstance().getModule(moduleName);
        if (module == null) {
            throw new P11TokenException("could not find RemoteP11Module '" + moduleName + "'");
        }
        return module;
    }
}
