/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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
import java.security.Security;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xipki.scep.client.test.MyUtil;
import org.xipki.scep.message.CaCaps;
import org.xipki.security.X509Cert;
import org.xipki.util.Args;

/**
 * SCEP server.
 *
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

  private X509Cert caCert;

  private X509Cert raCert;

  private X509Cert nextCaCert;

  private X509Cert nextRaCert;

  public ScepServer(String name, CaCaps caCaps, boolean withRa, boolean withNextCa,
      boolean generateCrl, ScepControl control) {
    this.name = Args.notBlank(name, "name");
    this.caCaps = Args.notNull(caCaps, "caCaps");
    this.control = Args.notNull(control, "control");
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

  public ScepServlet getServlet()
      throws Exception {
    if (servlet != null) {
      return servlet;
    }

    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
    X500Name rcaSubject;
    kpGen.initialize(2048);
    KeyPair keypair = kpGen.generateKeyPair();
    // CHECKSTYLE:SKIP
    PrivateKey rcaKey = keypair.getPrivate();
    rcaSubject = new X500Name("CN=RCA1, OU=emulator, O=myorg.org, C=DE");

    kpGen.initialize(2048);
    keypair = kpGen.generateKeyPair();

    SubjectPublicKeyInfo pkInfo = MyUtil.createSubjectPublicKeyInfo(keypair.getPublic());
    X500Name subject = new X500Name("CN=CA1, OU=emulator, O=myorg.org, C=DE");
    this.caCert = MyUtil.issueSubCaCert(rcaKey, rcaSubject, pkInfo, subject, BigInteger.valueOf(2),
        new Date(System.currentTimeMillis() - 10 * CaEmulator.MIN_IN_MS));
    CaEmulator ca = new CaEmulator(keypair.getPrivate(), this.caCert, generateCrl);

    RaEmulator ra = null;
    if (withRa) {
      kpGen.initialize(2048);
      keypair = kpGen.generateKeyPair();
      pkInfo = MyUtil.createSubjectPublicKeyInfo(keypair.getPublic());

      subject = new X500Name("CN=RA1, OU=emulator, O=myorg.org, C=DE");
      this.raCert = ca.generateCert(pkInfo, subject);
      ra = new RaEmulator(keypair.getPrivate(), this.raCert);
    }

    NextCaAndRa nextCaAndRa = null;
    if (withNextCa) {
      kpGen.initialize(2048);
      keypair = kpGen.generateKeyPair();

      pkInfo = MyUtil.createSubjectPublicKeyInfo(keypair.getPublic());
      subject = new X500Name("CN=CA2, OU=emulator, O=myorg.org, C=DE");

      Date startTime = new Date(System.currentTimeMillis() + 365 * CaEmulator.DAY_IN_MS);
      this.nextCaCert = MyUtil.issueSubCaCert(rcaKey, rcaSubject, pkInfo, subject,
              BigInteger.valueOf(2), startTime);
      CaEmulator tmpCa = new CaEmulator(keypair.getPrivate(), this.nextCaCert, generateCrl);

      if (withRa) {
        kpGen.initialize(2048);
        keypair = kpGen.generateKeyPair();
        pkInfo = MyUtil.createSubjectPublicKeyInfo(keypair.getPublic());

        subject = new X500Name("CN=RA2, OU=emulator, O=myorg.org, C=DE");
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

  public X509Cert getCaCert() {
    return caCert;
  }

  public X509Cert getRaCert() {
    return raCert;
  }

  public X509Cert getNextCaCert() {
    return nextCaCert;
  }

  public X509Cert getNextRaCert() {
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

}
