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
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.EdECConstants;
import org.xipki.security.SecurityFactory;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.P11CryptService;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.qa.JceSignSpeed;
import org.xipki.security.qa.P11KeyGenSpeed;
import org.xipki.security.qa.P11SignSpeed;
import org.xipki.security.qa.P12KeyGenSpeed;
import org.xipki.security.qa.P12SignSpeed;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.Args;
import org.xipki.util.BenchmarkExecutor;
import org.xipki.util.Hex;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Enumeration;
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

    public static class DSA extends KeyControl {
      private final int plen;
      private final int qlen;

      public DSA(int plen, int qlen) {
        this.plen = plen;
        this.qlen = qlen;
      }

      public int plen() {
        return plen;
      }

      public int qlen() {
        return qlen;
      }

    } // class KeyControl

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

  public abstract static class BSpeedP11ActionQa extends BatchSpeedActionQa {

    @Reference (optional = true)
    protected P11CryptServiceFactory p11CryptServiceFactory;

    @Option(name = "--key-id", description = "id (hex) of the PKCS#11 key")
    private String hexKeyId;

    @Option(name = "--slot", description = "slot index")
    protected int slotIndex = 0;

    protected P11Slot getSlot() throws XiSecurityException, TokenException, IllegalCmdParamException {
      P11CryptService p11Service = p11CryptServiceFactory.getP11CryptService();
      P11Module module = p11Service.getModule();
      return module.getSlot(module.getSlotIdForIndex(slotIndex));
    }

    protected byte[] getKeyId() {
      return StringUtil.isBlank(hexKeyId) ? null : Hex.decode(hexKeyId);
    }

  } // class BSpeedP11Action

  @Command(scope = "xi", name = "bspeed-dsa-gen-p11",
      description = "performance test of PKCS#11 DSA key generation (batch)")
  @Service
  public static class BspeedDsaGenP11 extends BSpeedP11ActionQa {

    private final Queue<KeyControl.DSA> queue = getKeyControlDSA();

    @Override
    protected BenchmarkExecutor nextTester() throws Exception {
      KeyControl.DSA control = queue.poll();
      return (control == null) ? null : new P11KeyGenSpeed.DSA(getSlot(), control.plen(), control.qlen());
    }

    @Override
    protected int getNumThreads() {
      return (getKeyId() == null) ? super.getNumThreads() : 1;
    }

  } // class BspeedDsaGenP11

  @Command(scope = "xi", name = "bspeed-dsa-sign-p11",
      description = "performance test of PKCS#11 DSA signature creation (batch)")
  @Service
  public static class BspeedDsaSignP11 extends BSpeedP11ActionQa {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.DSASigAlgCompleter.class)
    private String signAlgo;

    private final Queue<KeyControl.DSA> queue = getKeyControlDSA();

    @Override
    protected BenchmarkExecutor nextTester() throws Exception {
      KeyControl.DSA control = queue.poll();
      if (control == null) {
        return null;
      }

      if (control.plen() == 1024) {
        if (!"SHA1withDSA".equalsIgnoreCase(signAlgo)) {
          throw new IllegalCmdParamException("only SHA1withDSA is permitted for DSA with 1024 bit");
        }
      }

      return new P11SignSpeed.DSA(securityFactory, getSlot(), getKeyId(), signAlgo, getNumThreads(),
          control.plen(), control.qlen());
    }

  } // class BspeedDsaSignP11

  @Command(scope = "xi", name = "bspeed-ec-gen-p11",
      description = "performance test of PKCS#11 EC key generation (batch)")
  @Service
  public static class BspeedEcGenP11 extends BSpeedP11ActionQa {

    private final Queue<KeyControl.EC> queue = getKeyControlEC();

    @Override
    protected BenchmarkExecutor nextTester() throws Exception {
      KeyControl.EC control = queue.poll();
      if (control == null) {
        return null;
      }

      return new P11KeyGenSpeed.EC(getSlot(), getCurveOid(control.curveName()));
    }

    protected int getNumThreads(int numThreads) {
      return (getKeyId() == null) ? numThreads : 1;
    }

  } // class BspeedEcGenP11

  @Command(scope = "xi", name = "bspeed-ec-sign-p11",
      description = "performance test of PKCS#11 EC signature creation (batch)")
  @Service
  public static class BspeedEcSignP11 extends BSpeedP11ActionQa {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.ECDSASigAlgCompleter.class)
    private String signAlgo;

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

      if (control == null) {
        return null;
      }

      return new P11SignSpeed.EC(securityFactory, getSlot(), getKeyId(), signAlgo, getNumThreads(),
          AlgorithmUtil.getCurveOidForCurveNameOrOid(control.curveName));
    }

  } // class BspeedEcSignP11

  @Command(scope = "xi", name = "bspeed-rsa-gen-p11",
      description = "performance test of PKCS#11 RSA key generation (batch)")
  @Service
  public static class BspeedRsaGenP11 extends BSpeedP11ActionQa {

    private final Queue<KeyControl.RSA> queue = getKeyControlRSA();

    @Override
    protected BenchmarkExecutor nextTester() throws Exception {
      KeyControl.RSA control = queue.poll();
      return (control == null) ? null
          : new P11KeyGenSpeed.RSA(getSlot(), control.modulusLen(), RSAKeyGenParameterSpec.F4);
    }

  } // class BspeedRsaGenP11

  @Command(scope = "xi", name = "bspeed-rsa-sign-p11",
      description = "performance test of PKCS#11 RSA signature creation (batch)")
  @Service
  public static class BspeedRsaSignP11 extends BSpeedP11ActionQa {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.RSASigAlgCompleter.class)
    private String signAlgo;

    private final Queue<KeyControl.RSA> queue = getKeyControlRSA();

    @Override
    protected BenchmarkExecutor nextTester() throws Exception {
      KeyControl.RSA control = queue.poll();
      return (control == null) ? null
          : new P11SignSpeed.RSA(securityFactory, getSlot(), getKeyId(), signAlgo, getNumThreads(),
                control.modulusLen(), RSAKeyGenParameterSpec.F4);
    }

  } // class BspeedRsaGenP11

  public abstract static class SpeedP11ActionQa extends SingleSpeedActionQa {

    @Reference (optional = true)
    protected P11CryptServiceFactory p11CryptServiceFactory;

    @Option(name = "--key-id", description = "id (hex) of the PKCS#11 key")
    private String hexKeyId;

    @Option(name = "--slot", description = "slot index")
    protected int slotIndex = 0;

    protected P11Slot getSlot()
        throws XiSecurityException, TokenException, IllegalCmdParamException {
      P11CryptService p11Service = p11CryptServiceFactory.getP11CryptService();
      P11Module module = p11Service.getModule();
      return module.getSlot(module.getSlotIdForIndex(slotIndex));
    }

    protected byte[] getKeyId() {
      return StringUtil.isBlank(hexKeyId) ? null : Hex.decode(hexKeyId);
    }

  } // class SpeedP11Action

  @Command(scope = "xi", name = "speed-dsa-gen-p11",
      description = "performance test of PKCS#11 DSA key generation")
  @Service
  public static class SpeedDsaGenP11 extends SpeedP11ActionQa {

    @Option(name = "--plen", description = "bit length of the prime")
    private Integer plen = 2048;

    @Option(name = "--qlen", description = "bit length of the sub-prime")
    private Integer qlen;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      if (qlen == null) {
        qlen = (plen >= 2048) ? 256 : 160;
      }
      return new P11KeyGenSpeed.DSA(getSlot(), plen, qlen);
    }

    @Override
    protected int getNumThreads() {
      return (getKeyId() == null) ? super.getNumThreads() : 1;
    }

  } // class SpeedDsaGenP11

  @Command(scope = "xi", name = "speed-dsa-sign-p11",
      description = "performance test of PKCS#11 DSA signature creation")
  @Service
  public static class SpeedDsaSignP11 extends SpeedP11SignActionQa {

    @Option(name = "--plen", description = "bit length of the prime")
    private Integer plen = 2048;

    @Option(name = "--qlen", description = "bit length of the sub-prime")
    private Integer qlen;

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.DSASigAlgCompleter.class)
    private String signAlgo;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      if (qlen == null) {
        qlen = (plen >= 2048) ? 256 : 160;
      }

      if (plen == 1024) {
        if (!"SHA1withDSA".equalsIgnoreCase(signAlgo)) {
          throw new IllegalCmdParamException("only SHA1withDSA is permitted for DSA with 1024 bit");
        }
      }

      return new P11SignSpeed.DSA(keyPresent, securityFactory, getSlot(), getKeyId(), keyLabel,
          signAlgo, getNumThreads(), plen, qlen);
    }

  } // class SpeedDsaSignP11

  @Command(scope = "xi", name = "speed-ec-gen-p11", description = "performance test of PKCS#11 EC key generation")
  @Service
  public static class SpeedEcGenP11 extends SpeedP11ActionQa {

    @Option(name = "--curve", required = true, description = "EC curve name")
    @Completion(Completers.ECCurveNameCompleter.class)
    private String curveName;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P11KeyGenSpeed.EC(getSlot(), getCurveOid(curveName));
    }

    @Override
    protected int getNumThreads() {
      return (getKeyId() == null) ? super.getNumThreads() : 1;
    }

  } // class SpeedEcGenP11

  @Command(scope = "xi", name = "speed-ec-sign-p11", description = "performance test of PKCS#11 EC signature creation")
  @Service
  public static class SpeedEcSignP11 extends SpeedP11SignActionQa {

    @Option(name = "--curve", description = "EC curve name")
    @Completion(Completers.ECCurveNameCompleter.class)
    private String curveName = "secp256r1";

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.ECDSASigAlgCompleter.class)
    private String signAlgo;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P11SignSpeed.EC(keyPresent, securityFactory, getSlot(), getKeyId(), keyLabel,
          signAlgo, getNumThreads(), AlgorithmUtil.getCurveOidForCurveNameOrOid(curveName));
    }

  } // class SpeedEcSignP11

  @Command(scope = "xi", name = "speed-ed-gen-p11",
      description = "performance test of PKCS#11 Edwards and montgomery EC key generation")
  @Service
  public static class SpeedEdGenP11 extends SpeedP11ActionQa {

    @Option(name = "--curve", required = true, description = "curve name")
    @Completion(Completers.EdCurveNameCompleter.class)
    private String curveName;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P11KeyGenSpeed.EC(getSlot(), getCurveOid(curveName));
    }

    @Override
    protected int getNumThreads() {
      return (getKeyId() == null) ? super.getNumThreads() : 1;
    }

  } // class SpeedEdGenP11

  @Command(scope = "xi", name = "speed-ed-sign-p11",
      description = "performance test of PKCS#11 EdDSA signature creation")
  @Service
  public static class SpeedEdSignP11 extends SpeedP11SignActionQa {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.EDDSASigAlgCompleter.class)
    private String signAlgo;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      ASN1ObjectIdentifier curveOid = EdECConstants.getCurveOid(signAlgo);
      if (curveOid == null) {
        throw new IllegalCmdParamException("invalid signAlgo " + signAlgo);
      }

      return new P11SignSpeed.EC(keyPresent, securityFactory, getSlot(), getKeyId(), keyLabel,
          signAlgo, getNumThreads(), curveOid);
    }

  } // class SpeedEdSignP11

  @Command(scope = "xi", name = "speed-hmac-sign-p11",
      description = "performance test of PKCS#11 HMAC signature creation")
  @Service
  public static class SpeedHmacSignP11 extends SpeedP11SignActionQa {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.HMACSigAlgCompleter.class)
    private String signAlgo;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P11SignSpeed.HMAC(keyPresent, securityFactory, getSlot(), getKeyId(), keyLabel,
          signAlgo, getNumThreads());
    }

  } // class SpeedHmacSignP11

  @Command(scope = "xi", name = "speed-rsa-gen-p11", description = "performance test of PKCS#11 RSA key generation")
  @Service
  public static class SpeedRsaGenP11 extends SpeedP11ActionQa {

    @Option(name = "--key-size", description = "keysize in bit")
    private Integer keysize = 2048;

    @Option(name = "--exponent", aliases = "-e", description = "public exponent")
    private String publicExponent = SecurityActions.TEXT_F4;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P11KeyGenSpeed.RSA(getSlot(), keysize, toBigInt(publicExponent));
    }

    @Override
    protected int getNumThreads() {
      return (getKeyId() == null) ? super.getNumThreads() : 1;
    }

  } // class SpeedRsaGenP11

  @Command(scope = "xi", name = "speed-rsa-sign-p11",
      description = "performance test of PKCS#11 RSA signature creation")
  @Service
  public static class SpeedRsaSignP11 extends SpeedP11SignActionQa {

    @Option(name = "--key-size", description = "keysize in bit")
    private Integer keysize = 2048;

    @Option(name = "-e", description = "public exponent")
    private String publicExponent = SecurityActions.TEXT_F4;

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.RSASigAlgCompleter.class)
    private String signAlgo;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P11SignSpeed.RSA(keyPresent, securityFactory, getSlot(), getKeyId(), keyLabel,
          signAlgo, getNumThreads(), keysize, toBigInt(publicExponent));
    }

  } // class SpeedRsaSignP11

  public abstract static class SpeedP11SignActionQa extends SpeedP11ActionQa {

    @Option(name = "--key-present", description = "the PKCS#11 key is present")
    protected Boolean keyPresent = Boolean.FALSE;

    @Option(name = "--key-label", description = "label of the PKCS#11 key")
    protected String keyLabel;

  } // class SpeedP11SignAction

  @Command(scope = "xi", name = "speed-sm2-gen-p11", description = "performance test of PKCS#11 SM2 key generation")
  @Service
  public static class SpeedSm2GenP11 extends SpeedP11ActionQa {

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P11KeyGenSpeed.SM2(getSlot());
    }

    @Override
    protected int getNumThreads() {
      return (getKeyId() == null) ? super.getNumThreads() : 1;
    }

  } // class SpeedSm2GenP11

  @Command(scope = "xi", name = "speed-sm2-sign-p11",
      description = "performance test of PKCS#11 SM2 signature creation")
  @Service
  public static class SpeedSm2SignP11 extends SpeedP11SignActionQa {

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P11SignSpeed.SM2(keyPresent, securityFactory, getSlot(), getKeyId(), keyLabel, getNumThreads());
    }

  } // class SpeedSm2SignP11

  @Command(scope = "xi", name = "bspeed-dsa-gen-p12",
      description = "performance test of PKCS#12 DSA key generation (batch)")
  @Service
  public static class BspeedDsaGenP12 extends BatchSpeedActionQa {

    private final Queue<KeyControl.DSA> queue = getKeyControlDSA();

    @Override
    protected BenchmarkExecutor nextTester() throws Exception {
      KeyControl.DSA control = queue.poll();
      return (control == null) ? null : new P12KeyGenSpeed.DSA(control.plen(), control.qlen(), securityFactory);
    }

  } // class BspeedDsaGenP12

  @Command(scope = "xi", name = "bspeed-dsa-sign-p12",
      description = "performance test of PKCS#12 DSA signature creation")
  @Service
  public static class BspeedDsaSignP12 extends BSpeedP12SignActionQa {

    private final Queue<KeyControl.DSA> queue = getKeyControlDSA();

    @Override
    protected BenchmarkExecutor nextTester() throws Exception {
      KeyControl.DSA control = queue.poll();
      if (control == null) {
        return null;
      }
      if (control.plen() == 1024) {
        signAlgo = "SHA1withDSA";
      }

      return new P12SignSpeed.DSA(securityFactory, signAlgo, getNumThreads(), control.plen(), control.qlen());
    }

  } // class BspeedDsaSignP12

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

  @Command(scope = "xi", name = "speed-dsa-gen-p12", description = "performance test of PKCS#12 DSA key generation")
  @Service
  public static class SpeedDsaGenP12 extends SingleSpeedActionQa {

    @Option(name = "--plen", description = "bit length of the prime")
    private Integer plen = 2048;

    @Option(name = "--qlen", description = "bit length of the sub-prime")
    private Integer qlen;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      if (qlen == null) {
        qlen = (plen >= 2048) ? 256 : 160;
      }
      return new P12KeyGenSpeed.DSA(plen, qlen, securityFactory);
    }

  } // class SpeedDsaGenP12

  @Command(scope = "xi", name = "speed-dsa-sign-p12",
      description = "performance test of PKCS#12 DSA signature creation")
  @Service
  public static class SpeedDsaSignP12 extends SpeedP12SignActionQa {

    @Option(name = "--plen", description = "bit length of the prime")
    private Integer plen = 2048;

    @Option(name = "--qlen", description = "bit length of the sub-prime")
    private Integer qlen;

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.DSASigAlgCompleter.class)
    private String signAlgo;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      if (qlen == null) {
        qlen = (plen >= 2048) ? 256 : 160;
      }
      return new P12SignSpeed.DSA(securityFactory, signAlgo, getNumThreads(), plen, qlen);
    }

  } // class SpeedDsaSignP12

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

  @Command(scope = "xi", name = "qa-batch-ec-p11",
      description = "(QA) generate EC keypairs for all known curves in PKCS#11 device")
  @Service
  public static class BECGenP11 extends P11Actions.P11KeyGenAction {
    @Override
    protected Object execute0() throws Exception {
      P11Slot slot = getSlot();

      String labelPrefix = label + "-";

      Enumeration allNames = ECNamedCurveTable.getNames();
      while (allNames.hasMoreElements()) {
        String curveName = (String) allNames.nextElement();

        ASN1ObjectIdentifier curveOid = EdECConstants.getCurveOid(curveName);
        if (curveOid == null) {
          curveOid = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveName);
        }

        if (curveOid == null) {
          System.out.println("!!! ignore unknown curve " + curveName);
          continue;
        }

        label = labelPrefix + curveName;
        finalize("EC", slot.generateECKeypair(curveOid, getControl()));
      }

      String[] edeccurves = new String[]{EdECConstants.ED25519, EdECConstants.ED448,
          EdECConstants.X25519, EdECConstants.X448};
      for (String curveName : edeccurves) {
        label = labelPrefix + curveName;
        finalize("EC", slot.generateECKeypair(EdECConstants.getCurveOid(curveName), getControl()));
      }
      return null;
    }
  }

  private static ASN1ObjectIdentifier getCurveOid(String curveName) {
    ASN1ObjectIdentifier curveOid = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveName);
    if (curveOid == null) {
      throw new IllegalArgumentException("unknown curveName " + curveName);
    }
    return curveOid;
  } // method getCurveOid

  private static Queue<KeyControl.DSA> getKeyControlDSA() {
    Queue<KeyControl.DSA> queue = new LinkedList<>();
    queue.add(new KeyControl.DSA(1024, 160));
    queue.add(new KeyControl.DSA(2048, 224));
    queue.add(new KeyControl.DSA(2048, 256));
    queue.add(new KeyControl.DSA(3072, 256));
    return queue;
  }

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
