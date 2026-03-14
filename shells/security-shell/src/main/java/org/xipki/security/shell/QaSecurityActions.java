// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.KeySpec;
import org.xipki.security.SecurityFactory;
import org.xipki.security.SignAlgo;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.qa.P11KeypairGenSpeed;
import org.xipki.security.qa.P11SignSpeed;
import org.xipki.security.qa.P12KeypairGenSpeed;
import org.xipki.security.qa.P12SignSpeed;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.XiAction;
import org.xipki.util.benchmark.BenchmarkExecutor;
import org.xipki.util.codec.Hex;
import org.xipki.util.misc.StringUtil;

import java.security.NoSuchAlgorithmException;

/**
 * Actions of QA for security.
 *
 * @author Lijun Liao (xipki)
 */

public class QaSecurityActions {

  private static KeySpec getKeySpec(String keySpec, SignAlgo signAlgo)
      throws NoSuchAlgorithmException {
    if (keySpec != null) {
      return KeySpec.ofKeySpec(keySpec);
    }

    if (signAlgo.isRSASigAlgo()) {
      return KeySpec.RSA2048;
    }

    switch (signAlgo) {
      case ECDSA_SHA1:
      case ECDSA_SHA224:
      case ECDSA_SHA3_224:
      case ECDSA_SHA256:
      case ECDSA_SHA3_256:
      case ECDSA_SHAKE128:
        return KeySpec.P256;
      case ECDSA_SHA384:
      case ECDSA_SHA3_384:
        return KeySpec.P384;
      case ECDSA_SHA512:
      case ECDSA_SHA3_512:
      case ECDSA_SHAKE256:
        return KeySpec.P521;
      case SM2_SM3:
        return KeySpec.SM2;
      case ED25519:
        return KeySpec.ED25519;
      case ED448:
        return KeySpec.ED448;
      case MLDSA44:
        return KeySpec.MLDSA44;
      case MLDSA65:
        return KeySpec.MLDSA65;
      case MLDSA87:
        return KeySpec.MLDSA87;
      case MLDSA44_ED25519:
        return KeySpec.MLDSA44_ED25519;
      case MLDSA44_P256:
        return KeySpec.MLDSA44_P256;
      case MLDSA44_RSA2048:
        return KeySpec.MLDSA44_RSA2048;
      case MLDSA65_P256:
        return KeySpec.MLDSA65_P256;
      case MLDSA65_ED25519:
        return KeySpec.MLDSA65_ED25519;
      case MLDSA65_BP256:
        return KeySpec.MLDSA65_BP256;
      case MLDSA65_P384:
        return KeySpec.MLDSA65_P384;
      case MLDSA65_RSA3072:
        return KeySpec.MLDSA65_RSA3072;
      case MLDSA65_RSA4096:
        return KeySpec.MLDSA65_RSA4096;
      case MLDSA87_ED448:
        return KeySpec.MLDSA87_ED448;
      case MLDSA87_P384:
        return KeySpec.MLDSA87_P384;
      case MLDSA87_P521:
        return KeySpec.MLDSA87_P521;
      case MLDSA87_BP384:
        return KeySpec.MLDSA87_BP384;
      case MLDSA87_RSA3072:
        return KeySpec.MLDSA87_RSA3072;
      case MLDSA87_RSA4096:
        return KeySpec.MLDSA87_RSA4096;
    }

    throw new NoSuchAlgorithmException("could not detect KeySpec");
  }

  public abstract static class QaSpeedAction extends XiAction {

    @Option(name = "--duration", description = "duration")
    private String duration = "30s";

    @Option(name = "--thread", description = "number of threads")
    private Integer numThreads = 5;

    @Reference
    protected SecurityFactory securityFactory;

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

  public abstract static class QaSpeedP11Action extends QaSpeedAction {

    @Reference (optional = true)
    protected P11CryptServiceFactory p11CryptServiceFactory;

    @Option(name = "--key-id", description = "id (hex) of the PKCS#11 key")
    private String hexKeyId;

    @Option(name = "--slot", description = "slot index")
    protected int slotIndex = 0;

    @Option(name = "--module", description = "Name of the PKCS#11 module.")
    @Completion(SecurityCompleters.P11ModuleNameCompleter.class)
    protected String moduleName = P11CryptServiceFactory.DEFAULT_P11MODULE_NAME;

    protected P11Slot getSlot()
        throws XiSecurityException, TokenException, IllegalCmdParamException {
      P11Module module = p11CryptServiceFactory.getP11Module(moduleName);
      if (module == null) {
        throw new IllegalCmdParamException("undefined module " + moduleName);
      }
      return module.getSlot(module.getSlotIdForIndex(slotIndex));
    }

    protected byte[] getKeyId() {
      return StringUtil.isBlank(hexKeyId) ? null : Hex.decode(hexKeyId);
    }

  } // class SpeedP11Action

  @Command(scope = "xi", name = "speed-keypair-p11",
      description = "performance test of PKCS#11 key generation")
  @Service
  public static final class SpeedKeypairGenP11 extends QaSpeedP11Action {

    @Option(name = "--keyspec", required = true, description = "Key spec")
    @Completion(SecurityCompleters.KeySpecCompleter.class)
    private String keyspec;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P11KeypairGenSpeed(getSlot(), getKeySpec(keyspec));
    }

    @Override
    protected int getNumThreads() {
      return (getKeyId() == null) ? super.getNumThreads() : 1;
    }

  } // class SpeedEcGenP11

  @Command(scope = "xi", name = "speed-sign-p11",
      description = "performance test of PKCS#11 signature creation")
  @Service
  public static final class SpeedSignP11 extends QaSpeedP11Action {

    @Option(name = "--keyspec", description = "Key spec")
    @Completion(SecurityCompleters.KeySpecCompleter.class)
    private String keyspec;

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(Completers.SigAlgCompleter.class)
    private String signAlgo;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      SignAlgo jSignAlgo = getSignAlgo(signAlgo);
      KeySpec jKeySpec = getKeySpec(keyspec, jSignAlgo);
      return new P11SignSpeed(securityFactory, getSlot(), jSignAlgo, jKeySpec, getNumThreads());
    }

  } // class SpeedP11SignAction

  @Command(scope = "xi", name = "speed-keypair-p12",
      description = "performance test of PKCS#12 keypair key generation")
  @Service
  public static class SpeedKeypairGenP12 extends QaSpeedAction {

    @Option(name = "--keyspec", required = true, description = "Key spec")
    @Completion(SecurityCompleters.KeySpecCompleter.class)
    private String keyspec;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P12KeypairGenSpeed(getKeySpec(keyspec), securityFactory);
    }

  }

  @Command(scope = "xi", name = "speed-sign-p12",
      description = "performance test of PKCS#12 signature creation")
  @Service
  public static class SpeedSignP12 extends QaSpeedAction {

    @Option(name = "--keyspec", description = "Key spec")
    @Completion(SecurityCompleters.KeySpecCompleter.class)
    private String keyspec;

    @Option(name = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(Completers.SigAlgCompleter.class)
    private String signAlgo;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      SignAlgo jSignAlgo = getSignAlgo(signAlgo);
      KeySpec jKeySpec = getKeySpec(keyspec, jSignAlgo);
      return new P12SignSpeed(securityFactory, jSignAlgo, jKeySpec, getNumThreads());
    }

  }

  private static SignAlgo getSignAlgo(String str) throws IllegalCmdParamException {
    try {
      return SignAlgo.getInstance(str);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalCmdParamException("invalid SignAlgo " + str);
    }
  }

  private static KeySpec getKeySpec(String str) throws IllegalCmdParamException {
    try {
      return KeySpec.ofKeySpec(str);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalCmdParamException(e);
    }
  }

}
