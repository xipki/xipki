/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2016 Lijun Liao
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

package org.xipki.scep.serveremulator;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Arrays;
import org.xipki.scep.crypto.HashAlgoType;
import org.xipki.scep.util.ParamUtil;
import org.xipki.scep.util.ScepUtil;

/**
 * @author Lijun Liao
 */

public class CAEmulator {
    public static final long MIN_IN_MS = 60L * 1000;
    public static final long DAY_IN_MS = 24L * 60 * MIN_IN_MS;

    private final PrivateKey cAKey;
    private final Certificate cACert;
    private final X500Name cASubject;
    private final byte[] cACertBytes;
    private final boolean generateCRL;

    private final Map<BigInteger, Certificate> serialCertMap
        = new HashMap<BigInteger, Certificate>();
    private final Map<X500Name, Certificate> reqSubjectCertMap
        = new HashMap<X500Name, Certificate>();
    private final AtomicLong serialNumber = new AtomicLong(2);
    private final AtomicLong crlNumber = new AtomicLong(2);
    private CertificateList crl;

    public CAEmulator(
            final PrivateKey cAKey,
            final Certificate cACert,
            final boolean generateCRL)
    throws CertificateEncodingException {
        ParamUtil.assertNotNull("cAKey", cAKey);
        ParamUtil.assertNotNull("cACert", cACert);

        this.cAKey = cAKey;
        this.cACert = cACert;
        this.cASubject = cACert.getSubject();
        this.generateCRL = generateCRL;
        try {
            this.cACertBytes = cACert.getEncoded();
        } catch (IOException e) {
            throw new CertificateEncodingException(e.getMessage(), e);
        }
    }

    public PrivateKey getCAKey() {
        return cAKey;
    }

    public Certificate getCACert() {
        return cACert;
    }

    public byte[] getCACertBytes() {
        return Arrays.clone(cACertBytes);
    }

    public boolean isGenerateCRL() {
        return generateCRL;
    }

    public Certificate generateCert(
            final CertificationRequest p10ReqInfo)
    throws Exception {
        // TODO: verify the PKCS#10 request
        CertificationRequestInfo reqInfo = p10ReqInfo.getCertificationRequestInfo();
        return generateCert(reqInfo.getSubjectPublicKeyInfo(), reqInfo.getSubject());
    }

    public Certificate generateCert(
            final SubjectPublicKeyInfo pubKeyInfo,
            final X500Name subjectDN)
    throws Exception {
        return generateCert(pubKeyInfo, subjectDN,
                new Date(System.currentTimeMillis() - 10 * CAEmulator.MIN_IN_MS));
    }

    public Certificate generateCert(
            final SubjectPublicKeyInfo pubKeyInfo,
            final X500Name subjectDN,
            final Date notBefore)
    throws Exception {
        Date notAfter = new Date(notBefore.getTime() + 730 * DAY_IN_MS);

        BigInteger _serialNumber = BigInteger.valueOf(serialNumber.getAndAdd(1));
        X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(
                cASubject,
                _serialNumber,
                notBefore,
                notAfter,
                subjectDN,
                pubKeyInfo);

        X509KeyUsage ku = new X509KeyUsage(
                    X509KeyUsage.digitalSignature
                    | X509KeyUsage.dataEncipherment
                    | X509KeyUsage.keyAgreement
                    | X509KeyUsage.keyEncipherment);
        certGenerator.addExtension(Extension.keyUsage, true, ku);
        BasicConstraints bc = new BasicConstraints(false);
        certGenerator.addExtension(Extension.basicConstraints, true, bc);

        String signatureAlgorithm = ScepUtil.getSignatureAlgorithm(cAKey, HashAlgoType.SHA256);
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(cAKey);
        Certificate asn1Cert = certGenerator.build(contentSigner).toASN1Structure();

        serialCertMap.put(_serialNumber, asn1Cert);
        reqSubjectCertMap.put(subjectDN, asn1Cert);
        return asn1Cert;
    }

    public Certificate getCert(
            final X500Name issuer,
            final BigInteger serialNumber) {
        if (!cASubject.equals(issuer)) {
            return null;
        }

        return serialCertMap.get(serialNumber);
    }

    public Certificate pollCert(
            final X500Name issuer,
            final X500Name subject) {
        if (!cASubject.equals(issuer)) {
            return null;
        }

        return reqSubjectCertMap.get(subject);
    }

    public synchronized CertificateList getCRL(
            final X500Name issuer,
            final BigInteger serialNumber)
    throws Exception {
        if (crl != null) {
            return crl;
        }

        Date thisUpdate = new Date();
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(cASubject, thisUpdate);
        Date nextUpdate = new Date(thisUpdate.getTime() + 30 * DAY_IN_MS);
        crlBuilder.setNextUpdate(nextUpdate);
        Date cAStartTime = cACert.getTBSCertificate().getStartDate().getDate();
        Date revocationTime = new Date(cAStartTime.getTime() + 1);
        if (revocationTime.after(thisUpdate)) {
            revocationTime = cAStartTime;
        }
        crlBuilder.addCRLEntry(BigInteger.valueOf(2), revocationTime, CRLReason.keyCompromise);
        crlBuilder.addExtension(Extension.cRLNumber, false,
                new ASN1Integer(crlNumber.getAndAdd(1)));

        String signatureAlgorithm = ScepUtil.getSignatureAlgorithm(cAKey, HashAlgoType.SHA256);
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(cAKey);
        X509CRLHolder _crl = crlBuilder.build(contentSigner);
        crl = _crl.toASN1Structure();
        return crl;
    }

}
