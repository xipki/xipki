/*
 * Copyright (c) 2015 Lijun Liao
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

package org.xipki.scep4j.serveremulator;

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
import org.xipki.audit.slf4j.impl.Slf4jAuditLoggingServiceImpl;
import org.xipki.scep4j.crypto.HashAlgoType;
import org.xipki.scep4j.message.CACaps;
import org.xipki.scep4j.util.ParamUtil;
import org.xipki.scep4j.util.ScepUtil;

/**
 * @author Lijun Liao
 */

public class ScepServer
{
    private final String name;
    private final CACaps caCaps;
    private final boolean withRA;
    private final boolean withNextCA;
    private final boolean generateCRL;
    private final ScepControl control;

    private Long maxSigningTimeBiasInMs;
    private ScepServlet servlet;
    private Certificate cACert;
    private Certificate rACert;
    private Certificate nextCACert;
    private Certificate nextRACert;

    public ScepServer(
            final String name,
            final CACaps caCaps,
            final boolean withRA,
            final boolean withNextCA,
            final boolean generateCRL,
            final ScepControl control)
    {
        ParamUtil.assertNotBlank("name", name);
        ParamUtil.assertNotNull("caCaps", caCaps);
        ParamUtil.assertNotNull("control", control);
        this.name = name;
        this.caCaps = caCaps;
        this.withRA = withRA;
        this.withNextCA = withNextCA;
        this.generateCRL = generateCRL;
        this.control = control;
    }

    public String getName()
    {
        return name;
    }

    public void setMaxSigningTimeBias(
            final long ms)
    {
        this.maxSigningTimeBiasInMs = ms;
    }

    public ScepServlet getServlet()
    throws Exception
    {
        if(servlet != null)
        {
            return servlet;
        }

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        X500Name rCASubject;
        PrivateKey rCAKey;

        {
            kpGen.initialize(2048);
            KeyPair keypair = kpGen.generateKeyPair();
            rCAKey = keypair.getPrivate();
            rCASubject = new X500Name("CN=RCA1, OU=emulator, O=xipki.org, C=DE");
        }

        CAEmulator ca;

        {
            kpGen.initialize(2048);
            KeyPair keypair = kpGen.generateKeyPair();

            SubjectPublicKeyInfo pkInfo = ScepUtil.createSubjectPublicKeyInfo(keypair.getPublic());
            X500Name subject = new X500Name("CN=CA1, OU=emulator, O=xipki.org, C=DE");
            this.cACert = issueSubCACert(
                    rCAKey,
                    rCASubject,
                    pkInfo,
                    subject,
                    BigInteger.valueOf(2),
                    new Date(System.currentTimeMillis() - 10 * CAEmulator.MIN_IN_MS));
            ca = new CAEmulator(keypair.getPrivate(), this.cACert, generateCRL);
        }

        RAEmulator ra = null;
        if(withRA)
        {
            kpGen.initialize(2048);
            KeyPair keypair = kpGen.generateKeyPair();
            SubjectPublicKeyInfo pkInfo = ScepUtil.createSubjectPublicKeyInfo(keypair.getPublic());

            X500Name subject = new X500Name("CN=RA1, OU=emulator, O=xipki.org, C=DE");
            this.rACert = ca.generateCert(pkInfo, subject);
            ra = new RAEmulator(keypair.getPrivate(), this.rACert);
        }

        NextCAandRA nextCAandRA = null;
        if(withNextCA)
        {
            kpGen.initialize(2048);
            KeyPair keypair = kpGen.generateKeyPair();

            SubjectPublicKeyInfo pkInfo = ScepUtil.createSubjectPublicKeyInfo(keypair.getPublic());
            X500Name subject = new X500Name("CN=CA2, OU=emulator, O=xipki.org, C=DE");

            Date startTime = new Date(System.currentTimeMillis() + 365 * CAEmulator.DAY_IN_MS);
            this.nextCACert = issueSubCACert(
                    rCAKey,
                    rCASubject,
                    pkInfo,
                    subject,
                    BigInteger.valueOf(2),
                    startTime);
            CAEmulator tmpCA = new CAEmulator(keypair.getPrivate(), this.nextCACert, generateCRL);

            if(withRA)
            {
                kpGen.initialize(2048);
                keypair = kpGen.generateKeyPair();
                pkInfo = ScepUtil.createSubjectPublicKeyInfo(keypair.getPublic());

                subject = new X500Name("CN=RA2, OU=emulator, O=xipki.org, C=DE");
                Date rAStartTime = new Date(startTime.getTime() + 10 * CAEmulator.DAY_IN_MS);
                this.nextRACert = tmpCA.generateCert(pkInfo, subject, rAStartTime);
            }

            nextCAandRA = new NextCAandRA(this.nextCACert, this.nextRACert);
        }

        ScepResponder scepResponder = new ScepResponder(caCaps, ca, ra, nextCAandRA, control);
        if(maxSigningTimeBiasInMs != null)
        {
            scepResponder.setMaxSigningTimeBias(maxSigningTimeBiasInMs);
        }

        this.servlet = new ScepServlet(scepResponder);
        this.servlet.setAuditLoggingService(new Slf4jAuditLoggingServiceImpl());
        return this.servlet;
    }

    private static Certificate issueSubCACert(
            final PrivateKey rCAKey,
            final X500Name issuer,
            final SubjectPublicKeyInfo pubKeyInfo,
            final X500Name subject,
            final BigInteger serialNumber,
            final Date startTime)
    throws CertIOException, OperatorCreationException
    {
        Date notAfter = new Date(startTime.getTime() + CAEmulator.DAY_IN_MS * 3650);
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

        String signatureAlgorithm = ScepUtil.getSignatureAlgorithm(rCAKey, HashAlgoType.SHA256);
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(rCAKey);
        return certGenerator.build(contentSigner).toASN1Structure();
    }

    public Certificate getCACert()
    {
        return cACert;
    }

    public Certificate getRACert()
    {
        return rACert;
    }

    public Certificate getNextCACert()
    {
        return nextCACert;
    }

    public Certificate getNextRACert()
    {
        return nextRACert;
    }

    public boolean isWithRA()
    {
        return withRA;
    }

    public boolean isWithNextCA()
    {
        return withNextCA;
    }

    public boolean isGenerateCRL()
    {
        return generateCRL;
    }

}
