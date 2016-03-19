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

package org.xipki.pki.scep.serveremulator;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.xipki.commons.audit.slf4j.impl.Slf4jAuditServiceImpl;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.pki.scep.crypto.HashAlgoType;
import org.xipki.pki.scep.message.CaCaps;
import org.xipki.pki.scep.util.ScepUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ScepServer {

    private final String name;

    private final CaCaps caCaps;

    private final boolean withRa;

    private final boolean withNextCa;

    private final boolean generateCrl;

    private final ScepControl control;

    private Long maxSigningTimeBiasInMs;

    private ScepServlet servlet;

    private Certificate caCert;

    private Certificate raCert;

    private Certificate nextCaCert;

    private Certificate nextRaCert;

    public ScepServer(
            final String name,
            final CaCaps caCaps,
            final boolean withRa,
            final boolean withNextCa,
            final boolean generateCrl,
            final ScepControl control) {
        this.name = ParamUtil.requireNonBlank("name", name);
        this.caCaps = ParamUtil.requireNonNull("caCaps", caCaps);
        this.control = ParamUtil.requireNonNull("control", control);
        this.withRa = withRa;
        this.withNextCa = withNextCa;
        this.generateCrl = generateCrl;
    }

    public String getName() {
        return name;
    }

    public void setMaxSigningTimeBias(
            final long ms) {
        this.maxSigningTimeBiasInMs = ms;
    }

    public ScepServlet getServlet()
    throws Exception {
        if (servlet != null) {
            return servlet;
        }

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        X500Name rcaSubject;
        kpGen.initialize(2048);
        KeyPair keypair = kpGen.generateKeyPair();
        // CHECKSTYLE:SKIP
        PrivateKey rcaKey = keypair.getPrivate();
        rcaSubject = new X500Name("CN=RCA1, OU=emulator, O=xipki.org, C=DE");

        kpGen.initialize(2048);
        keypair = kpGen.generateKeyPair();

        SubjectPublicKeyInfo pkInfo = ScepUtil.createSubjectPublicKeyInfo(keypair.getPublic());
        X500Name subject = new X500Name("CN=CA1, OU=emulator, O=xipki.org, C=DE");
        this.caCert = issueSubCaCert(
                rcaKey,
                rcaSubject,
                pkInfo,
                subject,
                BigInteger.valueOf(2),
                new Date(System.currentTimeMillis() - 10 * CaEmulator.MIN_IN_MS));
        CaEmulator ca = new CaEmulator(keypair.getPrivate(), this.caCert, generateCrl);

        RaEmulator ra = null;
        if (withRa) {
            kpGen.initialize(2048);
            keypair = kpGen.generateKeyPair();
            pkInfo = ScepUtil.createSubjectPublicKeyInfo(keypair.getPublic());

            subject = new X500Name("CN=RA1, OU=emulator, O=xipki.org, C=DE");
            this.raCert = ca.generateCert(pkInfo, subject);
            ra = new RaEmulator(keypair.getPrivate(), this.raCert);
        }

        NextCaAndRa nextCaAndRa = null;
        if (withNextCa) {
            kpGen.initialize(2048);
            keypair = kpGen.generateKeyPair();

            pkInfo = ScepUtil.createSubjectPublicKeyInfo(keypair.getPublic());
            subject = new X500Name("CN=CA2, OU=emulator, O=xipki.org, C=DE");

            Date startTime = new Date(System.currentTimeMillis() + 365 * CaEmulator.DAY_IN_MS);
            this.nextCaCert = issueSubCaCert(
                    rcaKey,
                    rcaSubject,
                    pkInfo,
                    subject,
                    BigInteger.valueOf(2),
                    startTime);
            CaEmulator tmpCa = new CaEmulator(keypair.getPrivate(), this.nextCaCert, generateCrl);

            if (withRa) {
                kpGen.initialize(2048);
                keypair = kpGen.generateKeyPair();
                pkInfo = ScepUtil.createSubjectPublicKeyInfo(keypair.getPublic());

                subject = new X500Name("CN=RA2, OU=emulator, O=xipki.org, C=DE");
                Date raStartTime = new Date(startTime.getTime() + 10 * CaEmulator.DAY_IN_MS);
                this.nextRaCert = tmpCa.generateCert(pkInfo, subject, raStartTime);
            } // end if(withRA)

            nextCaAndRa = new NextCaAndRa(this.nextCaCert, this.nextRaCert);
        } // end if(withNextCA)

        ScepResponder scepResponder = new ScepResponder(caCaps, ca, ra, nextCaAndRa, control);
        if (maxSigningTimeBiasInMs != null) {
            scepResponder.setMaxSigningTimeBias(maxSigningTimeBiasInMs);
        }

        this.servlet = new ScepServlet(scepResponder);
        this.servlet.setAuditService(new Slf4jAuditServiceImpl());
        return this.servlet;
    } // method getServlet

    public Certificate getCaCert() {
        return caCert;
    }

    public Certificate getRaCert() {
        return raCert;
    }

    public Certificate getNextCaCert() {
        return nextCaCert;
    }

    public Certificate getNextRaCert() {
        return nextRaCert;
    }

    public boolean isWithRa() {
        return withRa;
    }

    public boolean isWithNextCa() {
        return withNextCa;
    }

    public boolean isGenerateCrl() {
        return generateCrl;
    }

    private static Certificate issueSubCaCert(
            final PrivateKey rcaKey,
            final X500Name issuer,
            final SubjectPublicKeyInfo pubKeyInfo,
            final X500Name subject,
            final BigInteger serialNumber,
            final Date startTime)
    throws CertIOException, OperatorCreationException {
        Date notAfter = new Date(startTime.getTime() + CaEmulator.DAY_IN_MS * 3650);
        X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(
                issuer,
                serialNumber,
                startTime,
                notAfter,
                subject,
                pubKeyInfo);

        X509KeyUsage ku = new X509KeyUsage(
                    X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign);
        certGenerator.addExtension(Extension.keyUsage, true, ku);
        BasicConstraints bc = new BasicConstraints(0);
        certGenerator.addExtension(Extension.basicConstraints, true, bc);

        String signatureAlgorithm = ScepUtil.getSignatureAlgorithm(rcaKey, HashAlgoType.SHA256);
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(rcaKey);
        return certGenerator.build(contentSigner).toASN1Structure();
    }

}
