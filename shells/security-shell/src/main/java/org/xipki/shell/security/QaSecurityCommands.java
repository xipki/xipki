// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.security;

import org.xipki.security.KeySpec;
import org.xipki.security.SignAlgo;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.qa.P11KeypairGenSpeed;
import org.xipki.security.qa.P11SignSpeed;
import org.xipki.security.qa.P12KeypairGenSpeed;
import org.xipki.security.qa.P12SignSpeed;
import org.xipki.shell.Completion;
import org.xipki.shell.xi.Completers;
import org.xipki.util.benchmark.BenchmarkExecutor;
import org.xipki.util.codec.Hex;
import org.xipki.util.misc.StringUtil;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.security.NoSuchAlgorithmException;

/**
 * The QA security shell.
 *
 * @author Lijun Liao (xipki)
 */
public class QaSecurityCommands {
  abstract static class QaSpeedCommand extends SecurityCommands.SecurityCommand {

    @Option(names = "--duration", description = "duration")
    private String duration = "30s";

    @Option(names = "--thread", description = "number of threads")
    private Integer numThreads = 5;

    protected abstract BenchmarkExecutor getTester() throws Exception;

    protected int getNumThreads() {
      return numThreads;
    }

    @Override
    public void run() {
      try {
        getTester().setDuration(duration).setThreads(getNumThreads()).execute();
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  abstract static class QaSpeedP11Command extends QaSpeedCommand {

    @Option(names = "--key-id", description = "id (hex) of the PKCS#11 key")
    private String hexKeyId;

    @Option(names = "--slot", description = "slot index")
    protected int slotIndex;

    @Option(names = "--module", description = "name of the PKCS#11 module")
    @Completion(SecurityCompleters.P11ModuleNameCompleter.class)
    protected String moduleName = P11CryptServiceFactory.DEFAULT_P11MODULE_NAME;

    protected P11Slot getSlot() throws Exception {
      P11Module module = securities().p11CryptServiceFactory().getP11Module(moduleName);
      if (module == null) {
        throw new IllegalArgumentException("undefined module " + moduleName);
      }
      return module.getSlot(module.getSlotIdForIndex(slotIndex));
    }

    protected byte[] getKeyId() {
      return StringUtil.isBlank(hexKeyId) ? null : Hex.decode(hexKeyId);
    }
  }

  @Command(name = "speed-keypair-p12",
      description = "performance test of PKCS#12 keypair generation",
      mixinStandardHelpOptions = true)
  static class SpeedKeypairGenP12Command extends QaSpeedCommand {

    @Option(names = "--keyspec", required = true, description = "key spec")
    @Completion(SecurityCompleters.KeySpecCompleter.class)
    private String keyspec;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P12KeypairGenSpeed(getQaKeySpec(keyspec), securities().securityFactory());
    }
  }

  @Command(name = "speed-sign-p12", description = "performance test of PKCS#12 signature creation",
      mixinStandardHelpOptions = true)
  static class SpeedSignP12Command extends QaSpeedCommand {

    @Option(names = "--keyspec", description = "key spec")
    @Completion(SecurityCompleters.KeySpecCompleter.class)
    private String keyspec;

    @Option(names = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(Completers.SigAlgoCompleter.class)
    private String signAlgo;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      SignAlgo jSignAlgo = getQaSignAlgo(signAlgo);
      KeySpec jKeySpec = getQaKeySpec(keyspec, jSignAlgo);
      return new P12SignSpeed(securities().securityFactory(), jSignAlgo, jKeySpec, getNumThreads());
    }
  }

  @Command(name = "speed-keypair-p11",
      description = "performance test of PKCS#11 key generation", mixinStandardHelpOptions = true)
  static class SpeedKeypairGenP11Command extends QaSpeedP11Command {

    @Option(names = "--keyspec", required = true, description = "key spec")
    @Completion(SecurityCompleters.KeySpecCompleter.class)
    private String keyspec;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      return new P11KeypairGenSpeed(getSlot(), getQaKeySpec(keyspec));
    }

    @Override
    protected int getNumThreads() {
      return getKeyId() == null ? super.getNumThreads() : 1;
    }
  }

  @Command(name = "speed-sign-p11", description = "performance test of PKCS#11 signature creation",
      mixinStandardHelpOptions = true)
  static class SpeedSignP11Command extends QaSpeedP11Command {

    @Option(names = "--keyspec", description = "key spec")
    @Completion(SecurityCompleters.KeySpecCompleter.class)
    private String keyspec;

    @Option(names = "--sig-algo", required = true, description = "signature algorithm")
    @Completion(Completers.SigAlgoCompleter.class)
    private String signAlgo;

    @Override
    protected BenchmarkExecutor getTester() throws Exception {
      SignAlgo jSignAlgo = getQaSignAlgo(signAlgo);
      KeySpec jKeySpec = getQaKeySpec(keyspec, jSignAlgo);
      return new P11SignSpeed(
          securities().securityFactory(), getSlot(), jSignAlgo, jKeySpec, getNumThreads());
    }
  }

  private static SignAlgo getQaSignAlgo(String str) throws Exception {
    return SignAlgo.getInstance(str);
  }

  private static KeySpec getQaKeySpec(String str) throws Exception {
    return KeySpec.ofKeySpec(str);
  }

  private static KeySpec getQaKeySpec(String keySpec, SignAlgo signAlgo) throws Exception {
    if (keySpec != null) {
      return KeySpec.ofKeySpec(keySpec);
    }
    if (signAlgo.isRSASigAlgo()) {
      return KeySpec.RSA2048;
    }
    if (signAlgo.isECDSASigAlgo()) {
      return KeySpec.P256;
    } else if (signAlgo == SignAlgo.SM2_SM3) {
      return KeySpec.SM2;
    }
    switch (signAlgo) {
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
      default:
        throw new NoSuchAlgorithmException("could not detect KeySpec");
    }
  }

}
