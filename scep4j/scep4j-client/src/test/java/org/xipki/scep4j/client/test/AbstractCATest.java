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

package org.xipki.scep4j.client.test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.xipki.scep4j.client.CACertValidator;
import org.xipki.scep4j.client.CAIdentifier;
import org.xipki.scep4j.client.EnrolmentResponse;
import org.xipki.scep4j.client.PreprovisionedCACertValidator;
import org.xipki.scep4j.client.ScepClient;
import org.xipki.scep4j.message.AuthorityCertStore;
import org.xipki.scep4j.message.CACaps;
import org.xipki.scep4j.serveremulator.ScepControl;
import org.xipki.scep4j.serveremulator.ScepServer;
import org.xipki.scep4j.serveremulator.ScepServerContainer;
import org.xipki.scep4j.transaction.CACapability;
import org.xipki.scep4j.transaction.PkiStatus;
import org.xipki.scep4j.util.ScepUtil;

import junit.framework.Assert;

/**
 * @author Lijun Liao
 */

public abstract class AbstractCATest
{
    private final String secret = "preshared-secret";
    private ScepServerContainer scepServerContainer;
    private ScepServer scepServer;

    protected abstract CACapability[] getExcludedCACaps();

    protected boolean isWithRA()
    {
        return true;
    }

    protected boolean sendSignerCert()
    {
        return true;
    }

    protected boolean useInsecureAlgorithms()
    {
        return false;
    }

    protected boolean isWithNextCA()
    {
        return true;
    }

    protected boolean isSendCACert()
    {
        return false;
    }

    protected boolean isPendingCert()
    {
        return false;
    }

    protected boolean isGenerateCRL()
    {
        return true;
    }

    @Before
    public void init()
    {
        if(Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    protected CACaps getDefaultCACaps()
    {
        final CACaps caCaps = new CACaps();
        caCaps.addCapability(CACapability.DES3);
        caCaps.addCapability(CACapability.AES);
        caCaps.addCapability(CACapability.SHA1);
        caCaps.addCapability(CACapability.SHA256);
        caCaps.addCapability(CACapability.POSTPKIOperation);
        return caCaps;
    }

    @Before
    public synchronized void startScepServer()
    throws Exception
    {
        if(scepServerContainer == null)
        {
            CACaps caCaps = getExpectedCACaps();

            ScepControl control = new ScepControl(isSendCACert(), isPendingCert(),
                    sendSignerCert(), useInsecureAlgorithms(), secret);

            this.scepServer = new ScepServer(
                    "scep",
                    caCaps,
                    isWithRA(),
                    isWithNextCA(),
                    isGenerateCRL(),
                    control);
            this.scepServerContainer = new ScepServerContainer(8080, scepServer);
        }

        this.scepServerContainer.start();
    }

    @After
    public synchronized void stopScepServer()
    throws Exception
    {
        if(this.scepServerContainer != null)
        {
            this.scepServerContainer.stop();
        }
    }

    @Test
    public void test()
    throws Exception
    {
        CAIdentifier cAId = new CAIdentifier("http://localhost:8080/scep/pkiclient.exe", null);
        CACertValidator cACertValidator = new PreprovisionedCACertValidator(
                new X509CertificateObject(scepServer.getCACert()));
        ScepClient client = new ScepClient(cAId, cACertValidator);
        client.setUseInsecureAlgorithms(useInsecureAlgorithms());

        client.refresh();

        CACaps expCACaps = getExpectedCACaps();

        // CACaps
        {
            CACaps cACaps = client.getCACaps();
            Assert.assertEquals("CACaps", expCACaps, cACaps);
        }

        // CA certificate
        X509Certificate cACert;
        {
            Certificate expCACert = scepServer.getCACert();
            cACert = client.getAuthorityCertStore().getCACert();
            if(equals(expCACert, cACert) == false)
            {
                Assert.fail("Configured and received CA certificate not the same");
            }
        }

        boolean withRA = isWithRA();
        // RA
        if(withRA)
        {
            Certificate expRACert = scepServer.getRACert();
            X509Certificate rASigCert = client.getAuthorityCertStore().getSignatureCert();
            X509Certificate rAEncCert = client.getAuthorityCertStore().getEncryptionCert();
            Assert.assertEquals("RA certificate", rASigCert, rAEncCert);

            if(equals(expRACert, rASigCert) == false)
            {
                Assert.fail("Configured and received RA certificate not the same");
            }
        }

        // getNextCA
        if(isWithNextCA())
        {
            AuthorityCertStore nextCA = client.scepNextCACert();

            Certificate expNextCACert = scepServer.getNextCACert();
            X509Certificate nextCACert = nextCA.getCACert();
            if(equals(expNextCACert, nextCACert) == false)
            {
                Assert.fail("Configured and received next CA certificate not the same");
            }

            if(withRA)
            {
                Certificate expNextRACert = scepServer.getNextRACert();
                X509Certificate nextRASigCert = nextCA.getSignatureCert();
                X509Certificate nextRAEncCert = nextCA.getEncryptionCert();
                Assert.assertEquals("Next RA certificate", nextRASigCert, nextRAEncCert);

                if(equals(expNextRACert, nextRASigCert) == false)
                {
                    Assert.fail("Configured and received next RA certificate not the same");
                }
            }
        }

        // enrol
        CertificationRequest csr;

        X509Certificate selfSignedCert;
        X509Certificate enroledCert;
        X500Name issuerName = X500Name.getInstance(cACert.getSubjectX500Principal().getEncoded());
        PrivateKey privKey;
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
            kpGen.initialize(2048);
            KeyPair keypair = kpGen.generateKeyPair();
            privKey = keypair.getPrivate();
            SubjectPublicKeyInfo subjectPublicKeyInfo = ScepUtil.createSubjectPublicKeyInfo(keypair.getPublic());
            X500Name subject = new X500Name("CN=EE1, OU=emulator, O=xipki.org, C=DE");

            // first try without secret
            {
                PKCS10CertificationRequest p10Req = ScepUtil.generateRequest(
                        privKey, subjectPublicKeyInfo, subject, null, null);
                csr = p10Req.toASN1Structure();

                selfSignedCert = ScepUtil.generateSelfsignedCert(p10Req.toASN1Structure(), privKey);
                EnrolmentResponse enrolResp = client.scepPkcsReq(p10Req.toASN1Structure(), privKey, selfSignedCert);
                PkiStatus status = enrolResp.getPkcsRep().getPkiStatus();
                Assert.assertEquals("PkiStatus without secret", PkiStatus.FAILURE, status);
            }

            // first try invalid secret
            {
                PKCS10CertificationRequest p10Req = ScepUtil.generateRequest(
                        privKey, subjectPublicKeyInfo, subject, "invalid-" + secret, null);
                csr = p10Req.toASN1Structure();

                selfSignedCert = ScepUtil.generateSelfsignedCert(p10Req.toASN1Structure(), privKey);
                EnrolmentResponse enrolResp = client.scepPkcsReq(p10Req.toASN1Structure(), privKey, selfSignedCert);
                PkiStatus status = enrolResp.getPkcsRep().getPkiStatus();
                Assert.assertEquals("PkiStatus with invalid secret", PkiStatus.FAILURE, status);
            }

            PKCS10CertificationRequest p10Req = ScepUtil.generateRequest(
                    privKey, subjectPublicKeyInfo, subject, secret, null);
            csr = p10Req.toASN1Structure();

            selfSignedCert = ScepUtil.generateSelfsignedCert(p10Req.toASN1Structure(), privKey);
            EnrolmentResponse enrolResp = client.scepPkcsReq(p10Req.toASN1Structure(), privKey, selfSignedCert);

            List<X509Certificate> certs = enrolResp.getCertificates();
            Assert.assertTrue("number of received certificates", certs.size() > 0);
            X509Certificate cert = certs.get(0);
            Assert.assertNotNull("enroled certificate", cert);
            enroledCert = cert;
        }

        // certPoll
        {
            EnrolmentResponse enrolResp = client.scepCertPoll(
                    privKey, selfSignedCert, csr, issuerName);

            List<X509Certificate> certs = enrolResp.getCertificates();
            Assert.assertTrue("number of received certificates", certs.size() > 0);
            X509Certificate cert = certs.get(0);
            Assert.assertNotNull("enroled certificate", cert);
        }

        // getCert
        {
            List<X509Certificate> certs =
                    client.scepGetCert(privKey, selfSignedCert, issuerName, enroledCert.getSerialNumber());
            Assert.assertTrue("number of received certificates", certs.size() > 0);
            X509Certificate cert = certs.get(0);
            Assert.assertNotNull("received certificate", cert);
        }

        // getCRL
        {
            X509CRL crl = client.scepGetCRL(privKey, enroledCert, issuerName, enroledCert.getSerialNumber());
            Assert.assertNotNull("received CRL", crl);
        }

        // getNextCA
        {
            AuthorityCertStore nextCA = client.scepNextCACert();
            Assert.assertNotNull("nextCA", nextCA);
        }
    }

    private CACaps getExpectedCACaps()
    {
        CACaps caCaps = getDefaultCACaps();
        CACapability[] excludedCACaps = getExcludedCACaps();
        if(excludedCACaps != null)
        {
            for(CACapability m : excludedCACaps)
            {
                caCaps.removeCapability(m);
            }
        }
        if(isWithNextCA())
        {
            if(caCaps.containsCapability(CACapability.GetNextCACert) == false)
            {
                caCaps.addCapability(CACapability.GetNextCACert);
            }
        } else
        {
            caCaps.removeCapability(CACapability.GetNextCACert);
        }
        return caCaps;
    }
    private boolean equals(
            final Certificate bcCert,
            final X509Certificate cert)
    throws CertificateException, IOException
    {
        return Arrays.equals(cert.getEncoded(), bcCert.getEncoded());
    }

}
