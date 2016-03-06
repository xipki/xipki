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

package org.xipki.pki.scep.client.test;

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
import org.xipki.pki.scep.client.CaCertValidator;
import org.xipki.pki.scep.client.CaIdentifier;
import org.xipki.pki.scep.client.EnrolmentResponse;
import org.xipki.pki.scep.client.PreprovisionedCaCertValidator;
import org.xipki.pki.scep.client.ScepClient;
import org.xipki.pki.scep.message.AuthorityCertStore;
import org.xipki.pki.scep.message.CaCaps;
import org.xipki.pki.scep.serveremulator.ScepControl;
import org.xipki.pki.scep.serveremulator.ScepServer;
import org.xipki.pki.scep.serveremulator.ScepServerContainer;
import org.xipki.pki.scep.transaction.CaCapability;
import org.xipki.pki.scep.transaction.PkiStatus;
import org.xipki.pki.scep.util.ScepUtil;

import junit.framework.Assert;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class AbstractCaTest {

    private final String secret = "preshared-secret";

    private ScepServerContainer scepServerContainer;

    private ScepServer scepServer;

    protected abstract CaCapability[] getExcludedCaCaps();

    protected boolean isWithRa() {
        return true;
    }

    protected boolean sendSignerCert() {
        return true;
    }

    protected boolean useInsecureAlgorithms() {
        return false;
    }

    protected boolean isWithNextCa() {
        return true;
    }

    protected boolean isSendCaCert() {
        return false;
    }

    protected boolean isPendingCert() {
        return false;
    }

    protected boolean isGenerateCrl() {
        return true;
    }

    @Before
    public void init() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    protected CaCaps getDefaultCaCaps() {
        final CaCaps caCaps = new CaCaps();
        caCaps.addCapability(CaCapability.DES3);
        caCaps.addCapability(CaCapability.AES);
        caCaps.addCapability(CaCapability.SHA1);
        caCaps.addCapability(CaCapability.SHA256);
        caCaps.addCapability(CaCapability.POSTPKIOperation);
        return caCaps;
    }

    @Before
    public synchronized void startScepServer()
    throws Exception {
        if (scepServerContainer == null) {
            CaCaps caCaps = getExpectedCaCaps();

            ScepControl control = new ScepControl(isSendCaCert(), isPendingCert(),
                    sendSignerCert(), useInsecureAlgorithms(), secret);

            this.scepServer = new ScepServer(
                    "scep",
                    caCaps,
                    isWithRa(),
                    isWithNextCa(),
                    isGenerateCrl(),
                    control);
            this.scepServerContainer = new ScepServerContainer(8080, scepServer);
        }

        this.scepServerContainer.start();
    }

    @After
    public synchronized void stopScepServer()
    throws Exception {
        if (this.scepServerContainer != null) {
            this.scepServerContainer.stop();
        }
    }

    @Test
    public void test()
    throws Exception {
        CaIdentifier caId = new CaIdentifier("http://localhost:8080/scep/pkiclient.exe", null);
        CaCertValidator caCertValidator = new PreprovisionedCaCertValidator(
                new X509CertificateObject(scepServer.getCaCert()));
        ScepClient client = new ScepClient(caId, caCertValidator);
        client.setUseInsecureAlgorithms(useInsecureAlgorithms());

        client.refresh();

        CaCaps expCaCaps = getExpectedCaCaps();

        // CACaps
        CaCaps caCaps = client.getCaCaps();
        Assert.assertEquals("CACaps", expCaCaps, caCaps);

        // CA certificate
        Certificate expCaCert = scepServer.getCaCert();
        X509Certificate caCert = client.getAuthorityCertStore().getCaCert();
        if (!equals(expCaCert, caCert)) {
            Assert.fail("Configured and received CA certificate not the same");
        }

        boolean withRa = isWithRa();
        // RA
        if (withRa) {
            Certificate expRaCert = scepServer.getRaCert();
            X509Certificate raSigCert = client.getAuthorityCertStore().getSignatureCert();
            X509Certificate raEncCert = client.getAuthorityCertStore().getEncryptionCert();
            Assert.assertEquals("RA certificate", raSigCert, raEncCert);

            if (!equals(expRaCert, raSigCert)) {
                Assert.fail("Configured and received RA certificate not the same");
            }
        }

        // getNextCA
        if (isWithNextCa()) {
            AuthorityCertStore nextCa = client.scepNextCaCert();

            Certificate expNextCaCert = scepServer.getNextCaCert();
            X509Certificate nextCaCert = nextCa.getCaCert();
            if (!equals(expNextCaCert, nextCaCert)) {
                Assert.fail("Configured and received next CA certificate not the same");
            }

            if (withRa) {
                Certificate expNextRaCert = scepServer.getNextRaCert();
                X509Certificate nextRaSigCert = nextCa.getSignatureCert();
                X509Certificate nextRaEncCert = nextCa.getEncryptionCert();
                Assert.assertEquals("Next RA certificate", nextRaSigCert, nextRaEncCert);

                if (!equals(expNextRaCert, nextRaSigCert)) {
                    Assert.fail("Configured and received next RA certificate not the same");
                }
            }
        }

        // enrol
        CertificationRequest csr;

        X509Certificate selfSignedCert;
        X509Certificate enroledCert;
        X500Name issuerName = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
        PrivateKey privKey; {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
            kpGen.initialize(2048);
            KeyPair keypair = kpGen.generateKeyPair();
            privKey = keypair.getPrivate();
            SubjectPublicKeyInfo subjectPublicKeyInfo = ScepUtil.createSubjectPublicKeyInfo(
                    keypair.getPublic());
            X500Name subject = new X500Name("CN=EE1, OU=emulator, O=xipki.org, C=DE");

            // first try without secret
            PKCS10CertificationRequest p10Req = ScepUtil.generateRequest(
                    privKey, subjectPublicKeyInfo, subject, null, null);
            csr = p10Req.toASN1Structure();

            selfSignedCert = ScepUtil.generateSelfsignedCert(p10Req.toASN1Structure(), privKey);
            EnrolmentResponse enrolResp = client.scepPkcsReq(p10Req.toASN1Structure(), privKey,
                    selfSignedCert);
            PkiStatus status = enrolResp.getPkcsRep().getPkiStatus();
            Assert.assertEquals("PkiStatus without secret", PkiStatus.FAILURE, status);

            // first try invalid secret
            p10Req = ScepUtil.generateRequest(
                    privKey, subjectPublicKeyInfo, subject, "invalid-" + secret, null);
            csr = p10Req.toASN1Structure();

            selfSignedCert = ScepUtil.generateSelfsignedCert(p10Req.toASN1Structure(), privKey);
            enrolResp = client.scepPkcsReq(p10Req.toASN1Structure(), privKey,
                    selfSignedCert);
            status = enrolResp.getPkcsRep().getPkiStatus();
            Assert.assertEquals("PkiStatus with invalid secret", PkiStatus.FAILURE, status);

            p10Req = ScepUtil.generateRequest(
                    privKey, subjectPublicKeyInfo, subject, secret, null);
            csr = p10Req.toASN1Structure();

            selfSignedCert = ScepUtil.generateSelfsignedCert(p10Req.toASN1Structure(), privKey);
            enrolResp = client.scepPkcsReq(p10Req.toASN1Structure(), privKey,
                    selfSignedCert);

            List<X509Certificate> certs = enrolResp.getCertificates();
            Assert.assertTrue("number of received certificates", certs.size() > 0);
            X509Certificate cert = certs.get(0);
            Assert.assertNotNull("enroled certificate", cert);
            enroledCert = cert;
        }

        // certPoll
        EnrolmentResponse enrolResp = client.scepCertPoll(
                privKey, selfSignedCert, csr, issuerName);

        List<X509Certificate> certs = enrolResp.getCertificates();
        Assert.assertTrue("number of received certificates", certs.size() > 0);
        X509Certificate cert = certs.get(0);
        Assert.assertNotNull("enroled certificate", cert);

        // getCert
        certs = client.scepGetCert(
                privKey, selfSignedCert, issuerName, enroledCert.getSerialNumber());
        Assert.assertTrue("number of received certificates", certs.size() > 0);
        cert = certs.get(0);
        Assert.assertNotNull("received certificate", cert);

        // getCRL
        X509CRL crl = client.scepGetCrl(privKey, enroledCert, issuerName,
                enroledCert.getSerialNumber());
        Assert.assertNotNull("received CRL", crl);

        // getNextCA
        AuthorityCertStore nextCa = client.scepNextCaCert();
        Assert.assertNotNull("nextCa", nextCa);
    }

    private CaCaps getExpectedCaCaps() {
        CaCaps caCaps = getDefaultCaCaps();
        CaCapability[] excludedCaCaps = getExcludedCaCaps();
        if (excludedCaCaps != null) {
            for (CaCapability m : excludedCaCaps) {
                caCaps.removeCapability(m);
            }
        }
        if (isWithNextCa()) {
            if (!caCaps.containsCapability(CaCapability.GetNextCACert)) {
                caCaps.addCapability(CaCapability.GetNextCACert);
            }
        } else {
            caCaps.removeCapability(CaCapability.GetNextCACert);
        }
        return caCaps;
    }

    private boolean equals(
            final Certificate bcCert,
            final X509Certificate cert)
    throws CertificateException, IOException {
        return Arrays.equals(cert.getEncoded(), bcCert.getEncoded());
    }

}
