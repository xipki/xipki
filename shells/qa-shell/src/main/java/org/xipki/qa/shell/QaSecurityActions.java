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

package org.xipki.qa.shell;

import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.qa.security.P11KeyGenSpeed;
import org.xipki.qa.security.P11SignSpeed;
import org.xipki.qa.security.P12KeyGenSpeed;
import org.xipki.qa.security.P12SignSpeed;
import org.xipki.security.EdECConstants;
import org.xipki.security.SecurityFactory;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.P11CryptService;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.security.pkcs11.P11TokenException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.Args;
import org.xipki.util.BenchmarkExecutor;
import org.xipki.util.Hex;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;

/**
 * Actions of QA for security.
 *
 * @author Lijun Liao
 */

public class QaSecurityActions {

  public static class KeyControl {

    //CHECKSTYLE:SKIP
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

    //CHECKSTYLE:SKIP
    public static class EC extends KeyControl {
      private final String curveName;

      public EC(String curveName) {
        this.curveName = Args.notBlank(curveName, "curveName");
      }

      public String curveName() {
        return curveName;
      }

    } // class EC

    //CHECKSTYLE:SKIP
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

  public abstract static class SecurityAction extends XiAction {

    @Reference
    protected SecurityFactory securityFactory;

  } // class SecurityAction

  public abstract static class SingleSpeedAction extends SecurityAction {

    @Option(name = "--duration", description = "duration")
    private String duration = "30s";

    @Option(name = "--thread", description = "number of threads")
    private Integer numThreads = 5;

    protected abstract BenchmarkExecutor getTester()
        throws Exception;

    @Override
    protected Object execute0()
        throws Exception {
      BenchmarkExecutor tester = getTester();
      tester.setDuration(duration);
      tester.setThreads(getNumThreads());

      tester.execute();
      return null;
    }

    protected int getNumThreads() {
      return numThreads;
    }

  } // class SingleSpeedAction

  public abstract static class BatchSpeedAction extends SecurityAction {

    private static final Logger LOG = LoggerFactory.getLogger(BatchSpeedAction.class);

    @Option(name = "--duration", description = "duration for each test case")
    private String duration = "10s";

    @Option(name = "--thread", description = "number of threads")
    private Integer numThreads = 5;

    protected abstract BenchmarkExecutor nextTester()
        throws Exception;

    @Override
    protected Object execute0()
        throws InterruptedException {
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

        tester.setDuration(duration);
        tester.setThreads(numThreads);
        tester.execute();
        if (tester.isInterrupted()) {
          throw new InterruptedException("cancelled by the user");
        }
      }
      return null;
    }

    // CHECKSTYLE:SKIP
    protected List<String> getECCurveNames() {
      return AlgorithmUtil.getECCurveNames();
    }

    protected int getNumThreads() {
      return numThreads;
    }

  } // class BatchSpeedAction

  public abstract static class BSpeedP11Action extends BatchSpeedAction {

    @Reference (optional = true)
    protected P11CryptServiceFactory p11CryptServiceFactory;

    @Option(name = "--key-id", description = "id (hex) of the PKCS#11 key")
    private String hexKeyId;

    @Option(name = "--slot", description = "slot index")
    protected int slotIndex = 0;

    @Option(name = "--module", description = "name of the PKCS#11 module.")
    @Completion(QaCompleters.P11ModuleNameCompleter.class)
    protected String moduleName = P11CryptServiceFactory.DEFAULT_P11MODULE_NAME;

    protected P11Slot getSlot()
        throws XiSecurityException, P11TokenException, IllegalCmdParamException {
      P11CryptService p11Service = p11CryptServiceFactory.getP11CryptService(moduleName);
      if (p11Service == null) {
        throw new IllegalCmdParamException("undefined module " + moduleName);
      }
      P11Module module = p11Service.getModule();
      P11SlotIdentifier slotId = module.getSlotIdForIndex(slotIndex);
      return module.getSlot(slotId);
    }

    protected byte[] getKeyId() {
      return StringUtil.isBlank(hexKeyId) ? null : Hex.decode(hexKeyId);
    }

  } // class BSpeedP11Action

  @Command(scope = "xi", name = "bspeed-dsa-gen-p11",
      description = "performance test of PKCS#11 DSA key generation (batch)")
  @Service
  public static class BspeedDsaGenP11 extends BSpeedP11Action {

    private final Queue<KeyControl.DSA> queue = new LinkedList<>();

    public BspeedDsaGenP11() {
      queue.add(new KeyControl.DSA(1024, 160));
      queue.add(new KeyControl.DSA(2048, 224));
      queue.add(new KeyControl.DSA(2048, 256));
      queue.add(new KeyControl.DSA(3072, 256));
    }

    @Override
    protected BenchmarkExecutor nextTester()
        throws Exception {
      KeyControl.DSA control = queue.poll();
      if (control == null) {
        return null;
      }

      return new P11KeyGenSpeed.DSA(getSlot(), getKeyId(), control.plen(), control.qlen());
    }

    @Override
    protected int getNumThreads() {
      return (getKeyId() == null) ? super.getNumThreads() : 1;
    }

  } // class BspeedDsaGenP11

  @Command(scope = "xi", name = "bspeed-dsa-sign-p11",
      description = "performance test of PKCS#11 DSA signature creation (batch)")
  @Service
  public static class BspeedDsaSignP11 extends BSpeedP11Action {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.DSASigAlgCompleter.class)
    private String sigAlgo;

    private final Queue<KeyControl.DSA> queue = new LinkedList<>();

    public BspeedDsaSignP11() {
      queue.add(new KeyControl.DSA(1024, 160));
      queue.add(new KeyControl.DSA(2048, 224));
      queue.add(new KeyControl.DSA(2048, 256));
      queue.add(new KeyControl.DSA(3072, 256));
    }

    @Override
    protected BenchmarkExecutor nextTester()
        throws Exception {
      KeyControl.DSA control = queue.poll();
      if (control == null) {
        return null;
      }

      if (control.plen() == 1024) {
        if (!"SHA1withDSA".equalsIgnoreCase(sigAlgo)) {
          throw new IllegalCmdParamException("only SHA1withDSA is permitted for DSA with 1024 bit");
        }
      }

      return new P11SignSpeed.DSA(securityFactory, getSlot(), getKeyId(), sigAlgo, getNumThreads(),
          control.plen(), control.qlen());
    }

  } // class BspeedDsaSignP11

  @Command(scope = "xi", name = "bspeed-ec-gen-p11",
      description = "performance test of PKCS#11 EC key generation (batch)")
  @Service
  public static class BspeedEcGenP11 extends BSpeedP11Action {

    private final Queue<KeyControl.EC> queue = new LinkedList<>();

    public BspeedEcGenP11() {
      for (String curveName : getECCurveNames()) {
        queue.add(new KeyControl.EC(curveName));
      }
    }

    @Override
    protected BenchmarkExecutor nextTester()
        throws Exception {
      KeyControl.EC control = queue.poll();
      if (control == null) {
        return null;
      }

      ASN1ObjectIdentifier curveOid = getCurveOid(control.curveName());
      return new P11KeyGenSpeed.EC(getSlot(), getKeyId(), curveOid);
    }

    protected int getNumThreads(int numThreads) {
      return (getKeyId() == null) ? numThreads : 1;
    }

  } // class BspeedEcGenP11

  @Command(scope = "xi", name = "bspeed-ec-sign-p11",
      description = "performance test of PKCS#11 EC signature creation (batch)")
  @Service
  public static class BspeedEcSignP11 extends BSpeedP11Action {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.ECDSASigAlgCompleter.class)
    private String sigAlgo;

    private final Queue<KeyControl.EC> queue = new LinkedList<>();

    public BspeedEcSignP11() {
      for (String curveName : getECCurveNames()) {
        queue.add(new KeyControl.EC(curveName));
      }
    }

    @Override
    protected BenchmarkExecutor nextTester()
        throws Exception {
      KeyControl.EC control = queue.poll();
      if (control == null) {
        return null;
      }

      return new P11SignSpeed.EC(securityFactory, getSlot(), getKeyId(), sigAlgo, getNumThreads(),
          AlgorithmUtil.getCurveOidForCurveNameOrOid(control.curveName));
    }

  } // class BspeedEcSignP11

  @Command(scope = "xi", name = "bspeed-rsa-gen-p11",
      description = "performance test of PKCS#11 RSA key generation (batch)")
  @Service
  public static class BspeedRsaGenP11 extends BSpeedP11Action {

    private final Queue<KeyControl.RSA> queue = new LinkedList<>();

    public BspeedRsaGenP11() {
      queue.add(new KeyControl.RSA(1024));
      queue.add(new KeyControl.RSA(2048));
      queue.add(new KeyControl.RSA(3072));
      queue.add(new KeyControl.RSA(4096));
    }

    @Override
    protected BenchmarkExecutor nextTester()
        throws Exception {
      KeyControl.RSA control = queue.poll();
      if (control == null) {
        return null;
      }

      return new P11KeyGenSpeed.RSA(getSlot(), getKeyId(), control.modulusLen(),
          toBigInt("0x10001"));
    }

  } // class BspeedRsaGenP11

  @Command(scope = "xi", name = "bspeed-rsa-sign-p11",
      description = "performance test of PKCS#11 RSA signature creation (batch)")
  @Service
  public static class BspeedRsaSignP11 extends BSpeedP11Action {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.RSASigAlgCompleter.class)
    private String sigAlgo;

    private final Queue<KeyControl.RSA> queue = new LinkedList<>();

    public BspeedRsaSignP11() {
      queue.add(new KeyControl.RSA(1024));
      queue.add(new KeyControl.RSA(2048));
      queue.add(new KeyControl.RSA(3072));
      queue.add(new KeyControl.RSA(4096));
    }

    @Override
    protected BenchmarkExecutor nextTester()
        throws Exception {
      KeyControl.RSA control = queue.poll();
      if (control == null) {
        return null;
      }

      return new P11SignSpeed.RSA(securityFactory, getSlot(), getKeyId(), sigAlgo, getNumThreads(),
          control.modulusLen(), toBigInt("0x10001"));
    }

  } // class BspeedRsaGenP11

  public abstract static class SpeedP11Action extends SingleSpeedAction {

    @Reference (optional = true)
    protected P11CryptServiceFactory p11CryptServiceFactory;

    @Option(name = "--key-id", description = "id (hex) of the PKCS#11 key")
    private String hexKeyId;

    @Option(name = "--slot", description = "slot index")
    protected int slotIndex = 0;

    @Option(name = "--module", description = "Name of the PKCS#11 module.")
    @Completion(QaCompleters.P11ModuleNameCompleter.class)
    protected String moduleName = P11CryptServiceFactory.DEFAULT_P11MODULE_NAME;

    protected P11Slot getSlot()
        throws XiSecurityException, P11TokenException, IllegalCmdParamException {
      P11CryptService p11Service = p11CryptServiceFactory.getP11CryptService(moduleName);
      if (p11Service == null) {
        throw new IllegalCmdParamException("undefined module " + moduleName);
      }
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
  public static class SpeedDsaGenP11 extends SpeedP11Action {

    @Option(name = "--plen", description = "bit length of the prime")
    private Integer plen = 2048;

    @Option(name = "--qlen", description = "bit length of the sub-prime")
    private Integer qlen;

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      if (qlen == null) {
        qlen = (plen >= 2048) ? 256 : 160;
      }
      return new P11KeyGenSpeed.DSA(getSlot(), getKeyId(), plen, qlen);
    }

    @Override
    protected int getNumThreads() {
      return (getKeyId() == null) ? super.getNumThreads() : 1;
    }

  } // class SpeedDsaGenP11

  @Command(scope = "xi", name = "speed-dsa-sign-p11",
      description = "performance test of PKCS#11 DSA signature creation")
  @Service
  public static class SpeedDsaSignP11 extends SpeedP11SignAction {

    @Option(name = "--plen", description = "bit length of the prime")
    private Integer plen = 2048;

    @Option(name = "--qlen", description = "bit length of the sub-prime")
    private Integer qlen;

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.DSASigAlgCompleter.class)
    private String sigAlgo;

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      if (qlen == null) {
        qlen = (plen >= 2048) ? 256 : 160;
      }

      if (plen == 1024) {
        if (!"SHA1withDSA".equalsIgnoreCase(sigAlgo)) {
          throw new IllegalCmdParamException("only SHA1withDSA is permitted for DSA with 1024 bit");
        }
      }

      return new P11SignSpeed.DSA(keyPresent, securityFactory, getSlot(), getKeyId(), keyLabel,
          sigAlgo, getNumThreads(), plen, qlen);
    }

  } // class SpeedDsaSignP11

  @Command(scope = "xi", name = "speed-ec-gen-p11",
      description = "performance test of PKCS#11 EC key generation")
  @Service
  public static class SpeedEcGenP11 extends SpeedP11Action {

    @Option(name = "--curve", required = true, description = "EC curve name")
    @Completion(Completers.ECCurveNameCompleter.class)
    private String curveName;

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      ASN1ObjectIdentifier curveOid = getCurveOid(curveName);
      return new P11KeyGenSpeed.EC(getSlot(), getKeyId(), curveOid);
    }

    @Override
    protected int getNumThreads() {
      return (getKeyId() == null) ? super.getNumThreads() : 1;
    }

  } // class SpeedEcGenP11

  @Command(scope = "xi", name = "speed-ec-sign-p11",
      description = "performance test of PKCS#11 EC signature creation")
  @Service
  public static class SpeedEcSignP11 extends SpeedP11SignAction {

    @Option(name = "--curve", description = "EC curve name")
    @Completion(Completers.ECCurveNameCompleter.class)
    private String curveName = "secp256r1";

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.ECDSASigAlgCompleter.class)
    private String sigAlgo;

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      return new P11SignSpeed.EC(keyPresent, securityFactory, getSlot(), getKeyId(), keyLabel,
          sigAlgo, getNumThreads(), AlgorithmUtil.getCurveOidForCurveNameOrOid(curveName));
    }

  } // class SpeedEcSignP11

  @Command(scope = "xi", name = "speed-ed-gen-p11",
      description = "performance test of PKCS#11 Edwards and montgomery EC key generation")
  @Service
  public static class SpeedEdGenP11 extends SpeedP11Action {

    @Option(name = "--curve", required = true, description = "curve name")
    @Completion(Completers.EdCurveNameCompleter.class)
    private String curveName;

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      ASN1ObjectIdentifier curveOid = getCurveOid(curveName);
      return new P11KeyGenSpeed.EC(getSlot(), getKeyId(), curveOid);
    }

    @Override
    protected int getNumThreads() {
      return (getKeyId() == null) ? super.getNumThreads() : 1;
    }

  } // class SpeedEdGenP11

  @Command(scope = "xi", name = "speed-ed-sign-p11",
      description = "performance test of PKCS#11 EdDSA signature creation")
  @Service
  public static class SpeedEdSignP11 extends SpeedP11SignAction {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.EDDSASigAlgCompleter.class)
    private String sigAlgo;

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      ASN1ObjectIdentifier curveOid = EdECConstants.getCurveOid(sigAlgo);
      if (curveOid == null) {
        throw new IllegalCmdParamException("invalid sigAlgo " + sigAlgo);
      }

      return new P11SignSpeed.EC(keyPresent, securityFactory, getSlot(), getKeyId(), keyLabel,
          sigAlgo, getNumThreads(), curveOid);
    }

  } // class SpeedEdSignP11

  @Command(scope = "xi", name = "speed-hmac-sign-p11",
      description = "performance test of PKCS#11 HMAC signature creation")
  @Service
  public static class SpeedHmacSignP11 extends SpeedP11SignAction {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.HMACSigAlgCompleter.class)
    private String sigAlgo;

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      return new P11SignSpeed.HMAC(keyPresent, securityFactory, getSlot(), getKeyId(), keyLabel,
          sigAlgo, getNumThreads());
    }

  } // class SpeedHmacSignP11

  @Command(scope = "xi", name = "speed-rsa-gen-p11",
      description = "performance test of PKCS#11 RSA key generation")
  @Service
  public static class SpeedRsaGenP11 extends SpeedP11Action {

    @Option(name = "--key-size", description = "keysize in bit")
    private Integer keysize = 2048;

    @Option(name = "--exponent", aliases = "-e", description = "public exponent")
    private String publicExponent = "0x10001";

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      return new P11KeyGenSpeed.RSA(getSlot(), getKeyId(), keysize, toBigInt(publicExponent));
    }

    @Override
    protected int getNumThreads() {
      return (getKeyId() == null) ? super.getNumThreads() : 1;
    }

  } // class SpeedRsaGenP11

  @Command(scope = "xi", name = "speed-rsa-sign-p11",
      description = "performance test of PKCS#11 RSA signature creation")
  @Service
  public static class SpeedRsaSignP11 extends SpeedP11SignAction {

    @Option(name = "--key-size", description = "keysize in bit")
    private Integer keysize = 2048;

    @Option(name = "-e", description = "public exponent")
    private String publicExponent = "0x10001";

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.RSASigAlgCompleter.class)
    private String sigAlgo;

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      return new P11SignSpeed.RSA(keyPresent, securityFactory, getSlot(), getKeyId(), keyLabel,
          sigAlgo, getNumThreads(), keysize, toBigInt(publicExponent));
    }

  } // class SpeedRsaSignP11

  public abstract static class SpeedP11SignAction extends SpeedP11Action {

    @Option(name = "--key-present", description = "the PKCS#11 key is present")
    protected Boolean keyPresent = Boolean.FALSE;

    @Option(name = "--key-label", description = "label of the PKCS#11 key")
    protected String keyLabel;

  } // class SpeedP11SignAction

  @Command(scope = "xi", name = "speed-sm2-gen-p11",
      description = "performance test of PKCS#11 SM2 key generation")
  @Service
  public static class SpeedSm2GenP11 extends SpeedP11Action {

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      return new P11KeyGenSpeed.SM2(getSlot(), getKeyId());
    }

    @Override
    protected int getNumThreads() {
      return (getKeyId() == null) ? super.getNumThreads() : 1;
    }

  } // class SpeedSm2GenP11

  @Command(scope = "xi", name = "speed-sm2-sign-p11",
      description = "performance test of PKCS#11 SM2 signature creation")
  @Service
  public static class SpeedSm2SignP11 extends SpeedP11SignAction {

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      return new P11SignSpeed.SM2(keyPresent, securityFactory, getSlot(), getKeyId(), keyLabel,
          getNumThreads());
    }

  } // class SpeedSm2SignP11

  @Command(scope = "xi", name = "bspeed-dsa-gen-p12",
      description = "performance test of PKCS#12 DSA key generation (batch)")
  @Service
  public static class BspeedDsaGenP12 extends BatchSpeedAction {

    private final Queue<KeyControl.DSA> queue = new LinkedList<>();

    public BspeedDsaGenP12() {
      queue.add(new KeyControl.DSA(1024, 160));
      queue.add(new KeyControl.DSA(2048, 224));
      queue.add(new KeyControl.DSA(2048, 256));
      queue.add(new KeyControl.DSA(3072, 256));
    }

    @Override
    protected BenchmarkExecutor nextTester()
        throws Exception {
      KeyControl.DSA control = queue.poll();
      return (control == null) ? null
          : new P12KeyGenSpeed.DSA(control.plen(), control.qlen(), securityFactory);
    }

  } // class BspeedDsaGenP12

  @Command(scope = "xi", name = "bspeed-dsa-sign-p12",
      description = "performance test of PKCS#12 DSA signature creation")
  @Service
  public static class BspeedDsaSignP12 extends BSpeedP12SignAction {

    private final Queue<KeyControl.DSA> queue = new LinkedList<>();

    public BspeedDsaSignP12() {
      queue.add(new KeyControl.DSA(1024, 160));
      queue.add(new KeyControl.DSA(2048, 224));
      queue.add(new KeyControl.DSA(2048, 256));
      queue.add(new KeyControl.DSA(3072, 256));
    }

    @Override
    protected BenchmarkExecutor nextTester()
        throws Exception {
      KeyControl.DSA control = queue.poll();
      if (control == null) {
        return null;
      }
      if (control.plen() == 1024) {
        sigAlgo = "SHA1withDSA";
      }

      return new P12SignSpeed.DSA(securityFactory, sigAlgo, getNumThreads(),
          control.plen(), control.qlen());
    }

  } // class BspeedDsaSignP12

  @Command(scope = "xi", name = "bspeed-ec-gen-p12",
      description = "performance test of PKCS#12 EC key generation (batch)")
  @Service
  public static class BspeedEcGenP12 extends BatchSpeedAction {

    private final Queue<KeyControl.EC> queue = new LinkedList<>();

    public BspeedEcGenP12() {
      for (String curveName : getECCurveNames()) {
        queue.add(new KeyControl.EC(curveName));
      }
    }

    @Override
    protected BenchmarkExecutor nextTester()
        throws Exception {
      KeyControl.EC control = queue.poll();
      ASN1ObjectIdentifier curveOid = getCurveOid(control.curveName());
      return (control == null) ? null : new P12KeyGenSpeed.EC(curveOid, securityFactory);
    }

  } // class BspeedEcGenP12

  @Command(scope = "xi", name = "bspeed-ec-sign-p12",
      description = "performance test of PKCS#12 EC signature creation (batch)")
  @Service
  public static class BspeedEcSignP12 extends BSpeedP12SignAction {

    private final Queue<KeyControl.EC> queue = new LinkedList<>();

    public BspeedEcSignP12() {
      for (String curveName : getECCurveNames()) {
        queue.add(new KeyControl.EC(curveName));
      }
    }

    @Override
    protected BenchmarkExecutor nextTester()
        throws Exception {
      KeyControl.EC control = queue.poll();
      return (control == null) ? null
          : new P12SignSpeed.EC(securityFactory, sigAlgo, getNumThreads(),
                  getCurveOid(control.curveName()));
    }

  } // class BspeedEcSignP12

  @Command(scope = "xi", name = "bspeed-rsa-gen-p12",
      description = "performance test of PKCS#12 RSA key generation (batch)")
  @Service
  public static class BspeedRsaGenP12 extends BatchSpeedAction {

    private final Queue<KeyControl.RSA> queue = new LinkedList<>();

    public BspeedRsaGenP12() {
      queue.add(new KeyControl.RSA(1024));
      queue.add(new KeyControl.RSA(2048));
      queue.add(new KeyControl.RSA(3072));
      queue.add(new KeyControl.RSA(4096));
    }

    @Override
    protected BenchmarkExecutor nextTester()
        throws Exception {
      KeyControl.RSA control = queue.poll();
      return (control == null) ? null
          : new P12KeyGenSpeed.RSA(control.modulusLen(), toBigInt("0x10001"), securityFactory);
    }

  } // class BspeedRsaGenP12

  @Command(scope = "xi", name = "bspeed-rsa-sign-p12",
      description = "performance test of PKCS#12 RSA signature creation (batch)")
  @Service
  public static class BspeedRsaSignP12 extends BSpeedP12SignAction {

    private final Queue<KeyControl.RSA> queue = new LinkedList<>();

    public BspeedRsaSignP12() {
      queue.add(new KeyControl.RSA(1024));
      queue.add(new KeyControl.RSA(2048));
      queue.add(new KeyControl.RSA(3072));
      queue.add(new KeyControl.RSA(4096));
    }

    @Override
    protected BenchmarkExecutor nextTester()
        throws Exception {
      KeyControl.RSA control = queue.poll();
      return (control == null) ? null
        : new P12SignSpeed.RSA(securityFactory, sigAlgo, getNumThreads(),
            control.modulusLen(), toBigInt("0x10001"));
    }
  } // class BspeedRsaSignP12

  public abstract static class BSpeedP12SignAction extends BatchSpeedAction {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    protected String sigAlgo;

  }

  @Command(scope = "xi", name = "speed-gmac-sign-p12",
      description = "performance test of PKCS#12 AES GMAC signature creation")
  @Service
  // CHECKSTYLE:SKIP
  public static class SpeedP12AESGmacSignAction extends SpeedP12SignAction {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.GMACSigAlgCompleter.class)
    private String sigAlgo;

    public SpeedP12AESGmacSignAction() {
    }

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      return new P12SignSpeed.AESGmac(securityFactory, sigAlgo, getNumThreads());
    }

  } // class BSpeedP12SignAction

  @Command(scope = "xi", name = "speed-dsa-gen-p12",
      description = "performance test of PKCS#12 DSA key generation")
  @Service
  public static class SpeedDsaGenP12 extends SingleSpeedAction {

    @Option(name = "--plen", description = "bit length of the prime")
    private Integer plen = 2048;

    @Option(name = "--qlen", description = "bit length of the sub-prime")
    private Integer qlen;

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      if (qlen == null) {
        qlen = (plen >= 2048) ? 256 : 160;
      }
      return new P12KeyGenSpeed.DSA(plen, qlen, securityFactory);
    }

  } // class SpeedDsaGenP12

  @Command(scope = "xi", name = "speed-dsa-sign-p12",
      description = "performance test of PKCS#12 DSA signature creation")
  @Service
  public static class SpeedDsaSignP12 extends SpeedP12SignAction {

    @Option(name = "--plen", description = "bit length of the prime")
    private Integer plen = 2048;

    @Option(name = "--qlen", description = "bit length of the sub-prime")
    private Integer qlen;

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.DSASigAlgCompleter.class)
    private String sigAlgo;

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      if (qlen == null) {
        qlen = (plen >= 2048) ? 256 : 160;
      }
      return new P12SignSpeed.DSA(securityFactory, sigAlgo, getNumThreads(), plen, qlen);
    }

  } // class SpeedDsaSignP12

  @Command(scope = "xi", name = "speed-ec-gen-p12",
      description = "performance test of PKCS#12 EC key generation")
  @Service
  public static class SpeedEcGenP12 extends SingleSpeedAction {

    @Option(name = "--curve", required = true, description = "EC curve name")
    @Completion(Completers.ECCurveNameCompleter.class)
    private String curveName;

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      return new P12KeyGenSpeed.EC(getCurveOid(curveName), securityFactory);
    }

  } // class SpeedEcGenP12

  @Command(scope = "xi", name = "speed-ec-sign-p12",
      description = "performance test of PKCS#12 EC signature creation")
  @Service
  public static class SpeedEcSignP12 extends SpeedP12SignAction {

    @Option(name = "--curve", required = true, description = "EC curve name")
    @Completion(Completers.ECCurveNameCompleter.class)
    private String curveName;

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.ECDSASigAlgCompleter.class)
    private String sigAlgo;

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      return new P12SignSpeed.EC(securityFactory, sigAlgo, getNumThreads(),
          getCurveOid(curveName));
    }

  } // class SpeedEcSignP12

  @Command(scope = "xi", name = "speed-ed-gen-p12",
      description = "performance test of PKCS#12 Edwards and montgomery EC key generation")
  @Service
  public static class SpeedEdGenP12 extends SingleSpeedAction {

    @Option(name = "--curve", required = true, description = "curve name")
    @Completion(Completers.EdCurveNameCompleter.class)
    private String curveName;

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      return new P12KeyGenSpeed.EC(getCurveOid(curveName), securityFactory);
    }

  } // class SpeedEdGenP12

  @Command(scope = "xi", name = "speed-ed-sign-p12",
      description = "performance test of PKCS#12 EdDSA signature creation")
  @Service
  public static class SpeedEdSignP12 extends SpeedP12SignAction {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.EDDSASigAlgCompleter.class)
    private String sigAlgo;

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      ASN1ObjectIdentifier curveOid = EdECConstants.getCurveOid(sigAlgo);
      return new P12SignSpeed.EC(securityFactory, sigAlgo, getNumThreads(), curveOid);
    }

  } // class SpeedEdSignP12

  @Command(scope = "xi", name = "speed-hmac-sign-p12",
      description = "performance test of PKCS#12 HMAC signature creation")
  @Service
  public static class SpeedHmacSignP12 extends SpeedP12SignAction {

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.HMACSigAlgCompleter.class)
    private String sigAlgo;

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      return new P12SignSpeed.HMAC(securityFactory, sigAlgo, getNumThreads());
    }

  } // class SpeedHmacSignP12

  @Command(scope = "xi", name = "speed-rsa-gen-p12",
      description = "performance test of PKCS#12 RSA key generation")
  @Service
  public static class SpeedRsaGenP12 extends SingleSpeedAction {

    @Option(name = "--key-size", description = "keysize in bit")
    private Integer keysize = 2048;

    @Option(name = "-e", description = "public exponent")
    private String publicExponent = "0x10001";

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      return new P12KeyGenSpeed.RSA(keysize, toBigInt(publicExponent), securityFactory);
    }

  } // class SpeedRsaGenP12

  @Command(scope = "xi", name = "speed-rsa-sign-p12",
      description = "performance test of PKCS#12 RSA signature creation")
  @Service
  public static class SpeedRsaSignP12 extends SpeedP12SignAction {

    @Option(name = "--key-size", description = "keysize in bit")
    private Integer keysize = 2048;

    @Option(name = "-e", description = "public exponent")
    private String publicExponent = "0x10001";

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(QaCompleters.RSASigAlgCompleter.class)
    private String sigAlgo;

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      return new P12SignSpeed.RSA(securityFactory, sigAlgo, getNumThreads(), keysize,
          toBigInt(publicExponent));
    }

  } // class SpeedRsaSignP12

  public abstract static class SpeedP12SignAction extends SingleSpeedAction {

  } // class SpeedP12SignAction

  @Command(scope = "xi", name = "speed-sm2-gen-p12",
      description = "performance test of PKCS#12 SM2 key generation")
  @Service
  public static class SpeedSm2GenP12 extends SingleSpeedAction {

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      return new P12KeyGenSpeed.EC(GMObjectIdentifiers.sm2p256v1, securityFactory);
    }

  } // class SpeedSm2GenP12

  @Command(scope = "xi", name = "speed-sm2-sign-p12",
      description = "performance test of PKCS#12 SM2 signature creation")
  @Service
  public static class SpeedSm2SignP12 extends SpeedP12SignAction {

    @Override
    protected BenchmarkExecutor getTester()
        throws Exception {
      return new P12SignSpeed.SM2(securityFactory, getNumThreads());
    }

  } // class SpeedSm2SignP12

  private static ASN1ObjectIdentifier getCurveOid(String curveName) {
    ASN1ObjectIdentifier curveOid = EdECConstants.getCurveOid(curveName);
    if (curveOid == null) {
      curveOid = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveName);
    }

    if (curveOid == null) {
      throw new IllegalArgumentException("unknown curveName " + curveName);
    }
    return curveOid;
  } // method getCurveOid

}
