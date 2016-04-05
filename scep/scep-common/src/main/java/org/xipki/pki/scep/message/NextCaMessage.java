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

package org.xipki.pki.scep.message;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.pki.scep.crypto.ScepHashAlgoType;
import org.xipki.pki.scep.exception.MessageEncodingException;
import org.xipki.pki.scep.util.ScepUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class NextCaMessage {

    private X509Certificate caCert;

    private List<X509Certificate> raCerts;

    public NextCaMessage() {
    }

    public X509Certificate getCaCert() {
        return caCert;
    }

    public void setCaCert(
            final X509Certificate caCert) {
        this.caCert = caCert;
    }

    public List<X509Certificate> getRaCerts() {
        return raCerts;
    }

    public void setRaCerts(
            final List<X509Certificate> raCerts) {
        if (raCerts == null || raCerts.isEmpty()) {
            this.raCerts = null;
        } else {
            this.raCerts = Collections.unmodifiableList(
                    new ArrayList<X509Certificate>(raCerts));
        }
    }

    public ContentInfo encode(
            final PrivateKey signingKey,
            final X509Certificate signerCert,
            final X509Certificate[] cmsCertSet)
    throws MessageEncodingException {
        ParamUtil.requireNonNull("signingKey", signingKey);
        ParamUtil.requireNonNull("signerCert", signerCert);

        try {
            byte[] degenratedSignedDataBytes;
            try {
                CMSSignedDataGenerator degenerateSignedData = new CMSSignedDataGenerator();
                degenerateSignedData.addCertificate(new X509CertificateHolder(caCert.getEncoded()));
                if (raCerts != null && !raCerts.isEmpty()) {
                    for (X509Certificate m : raCerts) {
                        degenerateSignedData.addCertificate(
                                new X509CertificateHolder(m.getEncoded()));
                    }
                }

                degenratedSignedDataBytes = degenerateSignedData.generate(
                        new CMSAbsentContent()).getEncoded();
            } catch (CertificateEncodingException ex) {
                throw new MessageEncodingException(ex.getMessage(), ex);
            }

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

            // I don't known which hash algorithm is supported by the client, use SHA-1
            String signatureAlgo = getSignatureAlgorithm(signingKey, ScepHashAlgoType.SHA1);
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgo).build(signingKey);

            // signerInfo
            JcaSignerInfoGeneratorBuilder signerInfoBuilder = new JcaSignerInfoGeneratorBuilder(
                    new BcDigestCalculatorProvider());

            signerInfoBuilder.setSignedAttributeGenerator(
                    new DefaultSignedAttributeTableGenerator());

            SignerInfoGenerator signerInfo = signerInfoBuilder.build(signer, signerCert);
            generator.addSignerInfoGenerator(signerInfo);

            CMSTypedData cmsContent = new CMSProcessableByteArray(
                    CMSObjectIdentifiers.signedData,
                    degenratedSignedDataBytes);

            // certificateSet
            ScepUtil.addCmsCertSet(generator, cmsCertSet);
            return generator.generate(cmsContent, true).toASN1Structure();
        } catch (CMSException ex) {
            throw new MessageEncodingException(ex);
        } catch (CertificateEncodingException ex) {
            throw new MessageEncodingException(ex);
        } catch (IOException ex) {
            throw new MessageEncodingException(ex);
        } catch (OperatorCreationException ex) {
            throw new MessageEncodingException(ex);
        }
    } // method encode

    private static String getSignatureAlgorithm(
            final PrivateKey key,
            final ScepHashAlgoType hashAlgo) {
        String algorithm = key.getAlgorithm();
        if ("RSA".equalsIgnoreCase(algorithm)) {
            return hashAlgo.getName() + "withRSA";
        } else {
            throw new UnsupportedOperationException(
                    "getSignatureAlgorithm() for non-RSA is not supported yet.");
        }
    }

}
