/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.scep.serveremulator;

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
import org.xipki.scep.crypto.ScepHashAlgo;
import org.xipki.scep.message.CaCaps;
import org.xipki.scep.util.ScepUtil;

/**
 * TODO.
 * @author Lijun Liao
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

  public ScepServer(String name, CaCaps caCaps, boolean withRa, boolean withNextCa,
      boolean generateCrl, ScepControl control) {
    this.name = ScepUtil.requireNonBlank("name", name);
    this.caCaps = ScepUtil.requireNonNull("caCaps", caCaps);
    this.control = ScepUtil.requireNonNull("control", control);
    this.withRa = withRa;
    this.withNextCa = withNextCa;
    this.generateCrl = generateCrl;
  }

  public String getName() {
    return name;
  }

  public void setMaxSigningTimeBias(long ms) {
    this.maxSigningTimeBiasInMs = ms;
  }

  public ScepServlet getServlet() throws Exception {
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
    this.caCert = issueSubCaCert(rcaKey, rcaSubject, pkInfo, subject, BigInteger.valueOf(2),
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
      this.nextCaCert = issueSubCaCert(rcaKey, rcaSubject, pkInfo, subject,
              BigInteger.valueOf(2), startTime);
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

  private static Certificate issueSubCaCert(PrivateKey rcaKey, X500Name issuer,
      SubjectPublicKeyInfo pubKeyInfo, X500Name subject, BigInteger serialNumber,
      Date startTime) throws CertIOException, OperatorCreationException {
    Date notAfter = new Date(startTime.getTime() + CaEmulator.DAY_IN_MS * 3650);
    X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(issuer, serialNumber,
        startTime, notAfter, subject, pubKeyInfo);
    X509KeyUsage ku = new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign);
    certGenerator.addExtension(Extension.keyUsage, true, ku);
    BasicConstraints bc = new BasicConstraints(0);
    certGenerator.addExtension(Extension.basicConstraints, true, bc);

    String signatureAlgorithm = ScepUtil.getSignatureAlgorithm(rcaKey, ScepHashAlgo.SHA256);
    ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(rcaKey);
    return certGenerator.build(contentSigner).toASN1Structure();
  }

}
