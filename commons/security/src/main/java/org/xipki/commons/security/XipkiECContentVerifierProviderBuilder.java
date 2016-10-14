/*
 *
 * Copyright (c) 2013 - 2016 Lijun Liao
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

package org.xipki.commons.security;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentVerifierProviderBuilder;
import org.xipki.commons.security.pkcs12.DSAPlainDigestSigner;

/**
 * @author Lijun Liao
 * @since 2.1.0
 */

// CHECKSTYLE:SKIP
public class XipkiECContentVerifierProviderBuilder extends BcContentVerifierProviderBuilder {

    private DigestAlgorithmIdentifierFinder digestAlgorithmFinder;

    public XipkiECContentVerifierProviderBuilder(
            DigestAlgorithmIdentifierFinder digestAlgorithmFinder) {
        this.digestAlgorithmFinder = digestAlgorithmFinder;
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId)
        throws OperatorCreationException {
        boolean plainDsa = true;
        ASN1ObjectIdentifier oid = sigAlgId.getAlgorithm();
        Digest dig;
        if (BSIObjectIdentifiers.ecdsa_plain_SHA1.equals(oid)) {
            dig = new SHA1Digest();
        } else if (BSIObjectIdentifiers.ecdsa_plain_SHA224.equals(oid)) {
            dig = new SHA224Digest();
        } else if (BSIObjectIdentifiers.ecdsa_plain_SHA256.equals(oid)) {
            dig = new SHA256Digest();
        } else if (BSIObjectIdentifiers.ecdsa_plain_SHA384.equals(oid)) {
            dig = new SHA384Digest();
        } else if (BSIObjectIdentifiers.ecdsa_plain_SHA512.equals(oid)) {
            dig = new SHA512Digest();
        } else {
            plainDsa = false;
            AlgorithmIdentifier digAlg = digestAlgorithmFinder.find(sigAlgId);
            dig = digestProvider.get(digAlg);
        }

        if (!plainDsa) {
            return new DSADigestSigner(new ECDSASigner(), dig);
        } else {
            return new DSAPlainDigestSigner(new ECDSASigner(), dig);
        }
    }

    protected AsymmetricKeyParameter extractKeyParameters(SubjectPublicKeyInfo publicKeyInfo)
    throws IOException {
        return PublicKeyFactory.createKey(publicKeyInfo);
    }

}
