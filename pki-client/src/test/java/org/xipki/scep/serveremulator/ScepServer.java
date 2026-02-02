// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.serveremulator;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.xipki.scep.client.test.MyUtil;
import org.xipki.security.pkix.X509Cert;
import org.xipki.security.scep.message.CaCaps;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * SCEP server.
 *
 * @author Lijun Liao (xipki)
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

  public ScepServer(String name, CaCaps caCaps, boolean withRa,
                    boolean withNextCa, boolean generateCrl,
                    ScepControl control) {
    this.name = Args.notBlank(name, "name");
    this.caCaps = Args.notNull(caCaps, "caCaps");
    this.control = Args.notNull(control, "control");
    this.withRa = withRa;
    this.withNextCa = withNextCa;
    this.generateCrl = generateCrl;
  }

  public String name() {
    return name;
  }

  public void setMaxSigningTimeBias(long ms) {
    this.maxSigningTimeBiasInMs = ms;
  }

  public ScepServlet getServlet() throws Exception {
    if (servlet != null) {
      return servlet;
    }

    if (Security.getProvider("BC") == null) {
      Security.addProvider(KeyUtil.newBouncyCastleProvider());
    }

    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
    X500Name rcaSubject;
    kpGen.initialize(2048);
    KeyPair keypair = kpGen.generateKeyPair();
    PrivateKey rcaKey = keypair.getPrivate();
    rcaSubject = new X500Name("CN=RCA1, OU=emulator, O=myorg.org, C=DE");

    kpGen.initialize(2048);
    keypair = kpGen.generateKeyPair();

    SubjectPublicKeyInfo pkInfo =
        MyUtil.createSubjectPublicKeyInfo(keypair.getPublic());
    X500Name subject = new X500Name(
        "CN=CA1, OU=emulator, O=myorg.org, C=DE");
    this.caCert = MyUtil.issueSubCaCert(rcaKey, rcaSubject, pkInfo,
        subject, BigInteger.valueOf(2),
        Instant.now().minus(10, ChronoUnit.MINUTES));
    CaEmulator ca = new CaEmulator(keypair.getPrivate(), this.caCert,
        generateCrl);

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

      Instant startTime = Instant.now().plus(365, ChronoUnit.DAYS);
      this.nextCaCert = MyUtil.issueSubCaCert(rcaKey, rcaSubject, pkInfo,
          subject, BigInteger.valueOf(2), startTime);
      CaEmulator tmpCa = new CaEmulator(keypair.getPrivate(), this.nextCaCert,
          generateCrl);

      if (withRa) {
        kpGen.initialize(2048);
        keypair = kpGen.generateKeyPair();
        pkInfo = MyUtil.createSubjectPublicKeyInfo(keypair.getPublic());

        subject = new X500Name("CN=RA2, OU=emulator, O=myorg.org, C=DE");
        Instant raStartTime = Instant.now().plus(10, ChronoUnit.DAYS);
        this.nextRaCert = tmpCa.generateCert(pkInfo, subject, raStartTime);
      } // end if(withRA)

      nextCaAndRa = new NextCaAndRa(this.nextCaCert, this.nextRaCert);
    } // end if(withNextCA)

    SimulatorScepResponder scepResponder =
        new SimulatorScepResponder(caCaps, ca, ra, nextCaAndRa, control);

    if (maxSigningTimeBiasInMs != null) {
      scepResponder.setMaxSigningTimeBias(maxSigningTimeBiasInMs);
    }

    this.servlet = new ScepServlet(scepResponder);
    return this.servlet;
  } // method getServlet

  public X509Cert caCert() {
    return caCert;
  }

  public X509Cert raCert() {
    return raCert;
  }

  public X509Cert nextCaCert() {
    return nextCaCert;
  }

  public X509Cert nextRaCert() {
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
