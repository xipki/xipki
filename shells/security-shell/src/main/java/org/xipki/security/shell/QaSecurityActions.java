// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.EdECConstants;
import org.xipki.security.SecurityFactory;
import org.xipki.security.qa.JceSignSpeed;
import org.xipki.security.qa.P12KeyGenSpeed;
import org.xipki.security.qa.P12SignSpeed;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.shell.Completers;
import org.xipki.shell.XiAction;
import org.xipki.util.Args;
import org.xipki.util.BenchmarkExecutor;
import org.xipki.util.LogUtil;

import java.security.spec.RSAKeyGenParameterSpec;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Queue;

/**
 * Actions of QA for security.
 *
 * @author Lijun Liao (xipki)
 */

public class QaSecurityActions {

  private static class KeyControl {

    public static class EC extends KeyControl {
      private final String curveName;

      public EC(String curveName) {
        this.curveName = Args.notBlank(curveName, "curveName");
      }

      public String curveName() {
        return curveName;
      }

    } // class EC

    public static class RSA extends KeyControl {
      private final int modulusLen;

      public RSA(int modulusLen) {
        this.modulusLen = modulusLen;
      }

      public int modulusLen() {
        return modulusLen;
      }

    } // class RSA

  } // class KeyControl

  public abstract static class QaSecurityAction extends XiAction {

    @Reference
    protected SecurityFactory securityFactory;

  } // class SecurityAction

  public abstract static class SingleSpeedActionQa extends QaSecurityAction {

    @Option(name = "--duration", description = "duration")
    private String duration = "30s";

    @Option(name = "--thread", description = "number of threads")
    private Integer numThreads = 5;

    protected abstract BenchmarkExecutor getTester() throws Exception;

    @Override
    protected Object execute0() throws Exception {
      getTester().setDuration(duration).setThreads(getNumThreads()).execute();
      return null;
    }

    protected int getNumThreads() {
      return numThreads;
    }

  } // class SingleSpeedAction

  public abstract static class BatchSpeedActionQa extends QaSecurityAction {

    private static final Logger LOG = LoggerFactory.getLogger(BatchSpeedActionQa.class);

    @Option(name = "--duration", description = "duration for each test case")
    private String duration = "10s";

    @Option(name = "--thread", description = "number of threads")
    private Integer numThreads = 5;

    protected abstract BenchmarkExecutor nextTester() throws Exception;

    @Override
    protected Object execute0() throws InterruptedException {
      while (true) {
        println("============================================");
        BenchmarkExecutor tester;
        try {
          tester = nextTester();
        } catch (Exception ex) {
          String msg = "could not get nextTester";
          LogUtil.error(LOG, ex, msg);
          println(msg + ": " + ex.getMessage());
          continue;
        }

        if (tester == null) {
          break;
        }

        tester.setDuration(duration).setThreads(numThreads).execute();
        if (tester.isInterrupted()) {
          throw new InterruptedException("cancelled by the user");
        }
      }
      return null;
    }

    protected int getNumThreads() {
      return numThreads;
    }

  } // class BatchSpeedAction

  @Command(scope = "xi", name = "bspeed-ec-gen-p12",
      description = "performance test of PKCS#12 EC key generation (batch)")
  @Service
  public static class BspeedEcGenP12 extends BatchSpeedActionQa {

    private final Queue<KeyControl.EC> queue = getKeyControlEC();

    @Override
    protected BenchmarkExecutor nextTester() throws Exception {
      KeyControl.EC control = queue.poll();
      return new P12KeyGenSpeed.EC(getCurveOid(control.curveName()), securityFactory);
    }

  } // class BspeedEcGenP12

  @Command(scope = "xi", name = "bspeed-ec-sign-p12",
      description = "performance test of PKCS#12 EC signature creation (batch)")
  @Service
  public static class BspeedEcSignP12 extends BSpeedP12SignActionQa {

    private final Queue<KeyControl.EC> queue = getKeyControlEC();

    @Override
    protected synchronized BenchmarkExecutor nextTester() throws Exception {
      KeyControl.EC control = queue.poll();

      boolean isSm2SignAlgo = signAlgo.toUpperCase(Locale.ROOT).contains("SM2");
      while (control != null) {
        boolean match = control.curveName.toUpperCase(Locale.ROOT).contains("SM2") == isSm2SignAlgo;
        if (match) {
          break;
        } else {
          control = queue.poll();
        }
      }

      return (control == null) ? null
          : new P12SignSpeed.EC(securityFactory, signAlgo, getNumThreads(), getCurveOid(control.curveName()));
    }

  } // class BspeedEcSignP12

  @Command(scope = "xi", name = "bspeed-rsa-gen-p12",
      description = "performance test of PKCS#12 RSA key generation (batch)")
  @Service
  public static class BspeedRsaGenP12 extends BatchSpeedActionQa {

    private final Queue<KeyControl.RSA> queue = getKeyControlRSA();

    @Override
    protected BenchmarkExecutor nextTester() throws Exception {
      KeyControl.RSA control = queue.poll();
      return (control == null) ? null
          : new P12KeyGenSpeed.RSA(control.modulusLen(), RSAKeyGenParameterSpec.F4, securityFactory);
    }

  } // class BspeedRsaGenP12

  @Command(scope = "xi", name = "bspeed-rsa-sign-p12",
      description = "performance test of PKCS#12 RSA signature creation (batch)")
  @Service
  public static class BspeedRsaSignP12 extends BSpeedP12SignActionQa {

    private final Queue<KeyControl.RSA> queue = getKeyControlRSA();

    @Override
    protected BenchmarkExecutor nextTester() throws Exception {
      KeyControl.RSA control = queue.poll();
      return (control == null) ? null
        : new P12SignSpeed.RSA(securityFactory, signAlgo, getNumThreads(),
          control.modulusLen(), RSAKeyGenParameterSpec.F4);
    }
  } // class BspeedRsaSignP12

  public abstract static class BSpeedP12SignActionQa extends BatchSpeedActionQa {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    protected String signAlgo;

  }

  @Command(scope = "xi", name = "speed-gmac-sign-p12",
      description = "performance test of PKCS#12 AES GMAC signature creation")
  @Service
  public static class SpeedP12AESGmacSignActionQa extends SpeedP12SignActionQa {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.GMACSigAlgCompleter.class)
    private String signAlgo;

    public SpeedP12AESGmacSignActionQa() {
    }

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P12SignSpeed.AESGmac(securityFactory, signAlgo, getNumThreads());
    }

  } // class BSpeedP12SignAction

  @Command(scope = "xi", name = "speed-ec-gen-p12", description = "performance test of PKCS#12 EC key generation")
  @Service
  public static class SpeedEcGenP12 extends SingleSpeedActionQa {

    @Option(name = "--curve", required = true, description = "EC curve name")
    @Completion(Completers.ECCurveNameCompleter.class)
    private String curveName;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P12KeyGenSpeed.EC(getCurveOid(curveName), securityFactory);
    }

  } // class SpeedEcGenP12

  @Command(scope = "xi", name = "speed-ec-sign-p12", description = "performance test of PKCS#12 EC signature creation")
  @Service
  public static class SpeedEcSignP12 extends SpeedP12SignActionQa {

    @Option(name = "--curve", required = true, description = "EC curve name")
    @Completion(Completers.ECCurveNameCompleter.class)
    private String curveName;

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.ECDSASigAlgCompleter.class)
    private String signAlgo;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P12SignSpeed.EC(securityFactory, signAlgo, getNumThreads(), getCurveOid(curveName));
    }

  } // class SpeedEcSignP12

  @Command(scope = "xi", name = "speed-ed-gen-p12",
      description = "performance test of PKCS#12 Edwards and montgomery EC key generation")
  @Service
  public static class SpeedEdGenP12 extends SingleSpeedActionQa {

    @Option(name = "--curve", required = true, description = "curve name")
    @Completion(Completers.EdCurveNameCompleter.class)
    private String curveName;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P12KeyGenSpeed.EC(getCurveOid(curveName), securityFactory);
    }

  } // class SpeedEdGenP12

  @Command(scope = "xi", name = "speed-ed-sign-p12",
      description = "performance test of PKCS#12 EdDSA signature creation")
  @Service
  public static class SpeedEdSignP12 extends SpeedP12SignActionQa {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.EDDSASigAlgCompleter.class)
    private String signAlgo;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P12SignSpeed.EC(securityFactory, signAlgo, getNumThreads(), EdECConstants.getCurveOid(signAlgo));
    }

  } // class SpeedEdSignP12

  @Command(scope = "xi", name = "speed-hmac-sign-p12",
      description = "performance test of PKCS#12 HMAC signature creation")
  @Service
  public static class SpeedHmacSignP12 extends SpeedP12SignActionQa {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.HMACSigAlgCompleter.class)
    private String signAlgo;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P12SignSpeed.HMAC(securityFactory, signAlgo, getNumThreads());
    }

  } // class SpeedHmacSignP12

  @Command(scope = "xi", name = "speed-rsa-gen-p12", description = "performance test of PKCS#12 RSA key generation")
  @Service
  public static class SpeedRsaGenP12 extends SingleSpeedActionQa {

    @Option(name = "--key-size", description = "keysize in bit")
    private Integer keysize = 2048;

    @Option(name = "-e", description = "public exponent")
    private String publicExponent = SecurityActions.TEXT_F4;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P12KeyGenSpeed.RSA(keysize, toBigInt(publicExponent), securityFactory);
    }

  } // class SpeedRsaGenP12

  @Command(scope = "xi", name = "speed-rsa-sign-p12",
      description = "performance test of PKCS#12 RSA signature creation")
  @Service
  public static class SpeedRsaSignP12 extends SpeedP12SignActionQa {

    @Option(name = "--key-size", description = "keysize in bit")
    private Integer keysize = 2048;

    @Option(name = "-e", description = "public exponent")
    private String publicExponent = SecurityActions.TEXT_F4;

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.RSASigAlgCompleter.class)
    private String signAlgo;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P12SignSpeed.RSA(securityFactory, signAlgo, getNumThreads(), keysize, toBigInt(publicExponent));
    }

  } // class SpeedRsaSignP12

  public abstract static class SpeedP12SignActionQa extends SingleSpeedActionQa {

  } // class SpeedP12SignAction

  @Command(scope = "xi", name = "speed-sm2-gen-p12", description = "performance test of PKCS#12 SM2 key generation")
  @Service
  public static class SpeedSm2GenP12 extends SingleSpeedActionQa {

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P12KeyGenSpeed.EC(GMObjectIdentifiers.sm2p256v1, securityFactory);
    }

  } // class SpeedSm2GenP12

  @Command(scope = "xi", name = "speed-sm2-sign-p12",
      description = "performance test of PKCS#12 SM2 signature creation")
  @Service
  public static class SpeedSm2SignP12 extends SpeedP12SignActionQa {

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P12SignSpeed.SM2(securityFactory, getNumThreads());
    }

  } // class SpeedSm2SignP12

  @Command(scope = "xi", name = "speed-sign-jce", description = "performance test of JCE signature creation")
  @Service
  public static class SpeedSignJce extends SingleSpeedActionQa {

    @Option(name = "--type", required = true, description = "JCE signer type")
    private String type;

    @Option(name = "--alias", required = true, description = "alias of the key in the JCE device")
    private String alias;

    @Option(name = "--algo", required = true, description = "signature algorithm")
    @Completion(SecurityCompleters.SignAlgoCompleter.class)
    private String algo;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new JceSignSpeed(securityFactory, type, alias, algo,
          "alias-" + alias + "_algo-" + algo, getNumThreads());
    }

  } // class SpeedEcSignP11

  private static ASN1ObjectIdentifier getCurveOid(String curveName) {
    ASN1ObjectIdentifier curveOid = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveName);
    if (curveOid == null) {
      throw new IllegalArgumentException("unknown curveName " + curveName);
    }
    return curveOid;
  } // method getCurveOid

  private static Queue<KeyControl.RSA> getKeyControlRSA() {
    Queue<KeyControl.RSA> queue = new LinkedList<>();
    queue.add(new KeyControl.RSA(1024));
    queue.add(new KeyControl.RSA(2048));
    queue.add(new KeyControl.RSA(3072));
    queue.add(new KeyControl.RSA(4096));
    return queue;
  }

  private static Queue<KeyControl.EC> getKeyControlEC() {
    Queue<KeyControl.EC> queue = new LinkedList<>();
    for (String curveName : AlgorithmUtil.getECCurveNames()) {
      queue.add(new KeyControl.EC(curveName));
    }
    return queue;
  }

}
