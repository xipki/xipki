// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.serveremulator;

import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.pkix.asn1.x500.X500Name;
import org.xipki.pkix.asn1.x509.KeyUsage;
import org.xipki.codec.util.Args;
import org.xipki.scep.client.test.MyUtil;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.scep.message.CaCaps;
import org.xipki.pkix.util.KeyUtil;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
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

  private boolean separateRaKeys;

  private ScepServlet servlet;

  private X509Cert caCert;

  private X509Cert raCert;

  private X509Cert raEncCert;

  private X509Cert nextCaCert;

  private X509Cert nextRaCert;

  public ScepServer(String name, CaCaps caCaps, boolean withRa,
                    boolean withNextCa, boolean generateCrl, ScepControl control) {
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

  /**
   * Use separate RA keys for signature and encryption.
   * @param separateRaKeys whether to use separate RA keys.
   */
  public void setSeparateRaKeys(boolean separateRaKeys) {
    this.separateRaKeys = separateRaKeys;
  }

  public ScepServlet getServlet() throws Exception {
    if (servlet != null) {
      return servlet;
    }

    SecureRandom rnd = KeyUtil.random();
    X500Name rcaSubject;
    KeyPair keypair = KeyUtil.generateKeyPair(KeySpec.RSA2048, rnd);
    PrivateKey rcaKey = keypair.getPrivate();
    rcaSubject = new X500Name("CN=RCA1, OU=emulator, O=myorg.org, C=DE");

    keypair = KeyUtil.generateKeyPair(KeySpec.RSA2048, rnd);

    SubjectPublicKeyInfo pkInfo = MyUtil.createSubjectPublicKeyInfo(keypair.getPublic());
    X500Name subject = new X500Name("CN=CA1, OU=emulator, O=myorg.org, C=DE");
    this.caCert = MyUtil.issueSubCaCert(rcaKey, rcaSubject, pkInfo,
        subject, BigInteger.valueOf(2), Instant.now().minus(10, ChronoUnit.MINUTES));
    CaEmulator ca = new CaEmulator(keypair.getPrivate(), this.caCert, generateCrl);

    RaEmulator ra = null;
    if (withRa) {
      keypair = KeyUtil.generateKeyPair(KeySpec.RSA2048, rnd);
      pkInfo = MyUtil.createSubjectPublicKeyInfo(keypair.getPublic());

      subject = new X500Name("CN=RA1, OU=emulator, O=myorg.org, C=DE");
      if (separateRaKeys) {
        Instant notBefore = Instant.now().minus(10, ChronoUnit.MINUTES);
        this.raCert = ca.generateCert(pkInfo, subject, notBefore,
            new KeyUsage(KeyUsage.digitalSignature));

        KeyPair encKeypair = KeyUtil.generateKeyPair(KeySpec.RSA2048, rnd);
        this.raEncCert = ca.generateCert(
            MyUtil.createSubjectPublicKeyInfo(encKeypair.getPublic()),
            new X500Name("CN=RA1-ENC, OU=emulator, O=myorg.org, C=DE"), notBefore,
            new KeyUsage(KeyUsage.keyEncipherment));
        ra = new RaEmulator(keypair.getPrivate(), this.raCert,
            encKeypair.getPrivate(), this.raEncCert);
      } else {
        this.raCert = ca.generateCert(pkInfo, subject);
        this.raEncCert = this.raCert;
        ra = new RaEmulator(keypair.getPrivate(), this.raCert);
      }
    }

    NextCaAndRa nextCaAndRa = null;
    if (withNextCa) {
      keypair = KeyUtil.generateKeyPair(KeySpec.RSA2048, rnd);

      pkInfo = MyUtil.createSubjectPublicKeyInfo(keypair.getPublic());
      subject = new X500Name("CN=CA2, OU=emulator, O=myorg.org, C=DE");

      Instant startTime = Instant.now().plus(365, ChronoUnit.DAYS);
      this.nextCaCert = MyUtil.issueSubCaCert(rcaKey, rcaSubject, pkInfo,
          subject, BigInteger.valueOf(2), startTime);
      CaEmulator tmpCa = new CaEmulator(keypair.getPrivate(), this.nextCaCert, generateCrl);

      if (withRa) {
        keypair = KeyUtil.generateKeyPair(KeySpec.RSA2048, rnd);
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

  public X509Cert raEncCert() {
    return raEncCert;
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
