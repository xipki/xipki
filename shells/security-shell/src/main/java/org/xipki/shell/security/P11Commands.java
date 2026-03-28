// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11SecretKeySpec;
import org.xipki.security.KeySpec;
import org.xipki.security.pkcs11.P11CompositeKey;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotId;
import org.xipki.security.util.KeyUtil;
import org.xipki.shell.Completion;
import org.xipki.shell.completer.FilePathCompleter;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Hex;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.StringUtil;
import org.xipki.util.password.PasswordResolverException;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Actions for PKCS#11 security.
 *
 * @author Lijun Liao (xipki)
 */
public class P11Commands {
  @Command(name = "keypair-p11", description = "generate keypair in PKCS#11 device",
      mixinStandardHelpOptions = true)
  static class KeypairP11Command extends P11KeyGenCommand {

    @Option(names = "--keyspec", required = true, description = "key spec")
    @Completion(SecurityCompleters.KeySpecCompleter.class)
    private String keyspecStr;

    @Override
    public void run() {
      try {
        KeySpec keySpec = KeySpec.ofKeySpec(keyspecStr);
        P11Slot slot = getSlot();
        NewKeyControl control = getControl();
        if (keySpec.isComposite() && control.id() != null) {
          throw new IllegalArgumentException("id is not allowed for composite keypair");
        }

        PKCS11KeyPairSpec spec = new PKCS11KeyPairSpec()
            .token(true).generateId(true).extractable(control.extractable())
            .sensitive(control.sensitive());
        Set<NewKeyControl.P11KeyUsage> usages = control.usages();
        if (usages == null) {
          if (keySpec.isRSA() || keySpec.isWeierstrassEC()) {
            spec.signVerify(true).decryptEncrypt(true).signVerifyRecover(true);
          } else if (keySpec.isEdwardsEC() || keySpec.isMldsa() || keySpec.isCompositeMLDSA()) {
            spec.signVerify(true);
          } else if (keySpec.isMontgomeryEC() || keySpec.isMlkem()) {
            spec.decryptEncrypt(true);
          } else if (keySpec.isCompositeMLKEM()) {
            spec.deEncapsulate(true);
            KeySpec tradKeySpec = keySpec.compositeTradVariant();
            if (tradKeySpec.isRSA()) {
              spec.decrypt(true);
            } else if (tradKeySpec.isMontgomeryEC() || tradKeySpec.isWeierstrassEC()) {
              spec.derive(true);
            }
          } else {
            spec.signVerify(true);
          }
        } else {
          for (NewKeyControl.P11KeyUsage usage : usages) {
            switch (usage) {
              case ENCRYPT:
                spec.encrypt(true);
                break;
              case DECRYPT:
                spec.decrypt(true);
                break;
              case DERIVE:
                spec.derive(true);
                break;
              case SIGN:
                spec.sign(true);
                break;
              case VERIFY:
                spec.verify(true);
                break;
              case SIGN_RECOVER:
                spec.signRecover(true);
                break;
              case VERIFY_RECOVER:
                spec.verifyRecover(true);
                break;
              case WRAP:
                spec.wrap(true);
                break;
              case UNWRAP:
                spec.unwrap(true);
                break;
              case ENCAPSULATE:
                spec.encapsulate(true);
                break;
              case DECAPSULATE:
                spec.decapsulate(true);
                break;
              default:
                break;
            }
          }
        }

        if (keySpec.isComposite()) {
          String coreLabel = label;
          if (StringUtil.startsWithIgnoreCase(label, P11CompositeKey.COMPOSITE_LABEL_PREFIX)) {
            coreLabel = label.substring(P11CompositeKey.COMPOSITE_LABEL_PREFIX.length());
          } else if (StringUtil.startsWithIgnoreCase(label,
                      P11CompositeKey.COMP_PQC_LABEL_PREFIX)) {
            coreLabel = label.substring(P11CompositeKey.COMP_PQC_LABEL_PREFIX.length());
          } else if (StringUtil.startsWithIgnoreCase(label,
                      P11CompositeKey.COMP_TRAD_LABEL_PREFIX)) {
            coreLabel = label.substring(P11CompositeKey.COMP_TRAD_LABEL_PREFIX.length());
          }

          PKCS11KeyPairSpec pqcSpec = spec.copy()
              .label(P11CompositeKey.COMP_PQC_LABEL_PREFIX + coreLabel);
          pqcSpec.derive(null).encrypt(null).decrypt(null);
          finalizeKey("PQC key of " + keyspecStr,
              slot.generateKeyPair(keySpec.compositePqcVariant(), pqcSpec));

          PKCS11KeyPairSpec tradSpec = spec.copy()
              .label(P11CompositeKey.COMP_TRAD_LABEL_PREFIX + coreLabel);
          tradSpec.encapsulate(null).decapsulate(null);
          finalizeKey("Trad key of " + keyspecStr,
              slot.generateKeyPair(keySpec.compositeTradVariant(), tradSpec));
        } else {
          spec.id(control.id()).label(label);
          finalizeKey(keyspecStr, slot.generateKeyPair(keySpec, spec));
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "delete-key-p11", description = "delete key in PKCS#11 device",
      mixinStandardHelpOptions = true)
  static class DeleteKeyP11Command extends P11SecurityCommand {

    @Option(names = "--id", description = "id (hex) of the private key")
    private String id;

    @Option(names = "--label", description = "label of the private key")
    private String label;

    @Option(names = {"--force", "-f"}, description = "remove identities without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    public void run() {
      try {
        boolean composite = label != null
            && StringUtil.startsWithIgnoreCase(label, P11CompositeKey.COMPOSITE_LABEL_PREFIX);
        if (composite) {
          if (id != null) {
            throw new IllegalArgumentException("id shall not be specified for composite key");
          }
          String coreLabel = label.substring(P11CompositeKey.COMPOSITE_LABEL_PREFIX.length());
          doDeleteKey(null, P11CompositeKey.COMP_PQC_LABEL_PREFIX + coreLabel);
          doDeleteKey(null, P11CompositeKey.COMP_TRAD_LABEL_PREFIX + coreLabel);
        } else {
          doDeleteKey(id, label);
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private void doDeleteKey(String hexId, String keyLabel) throws Exception {
      PKCS11KeyId identity = getIdentity(hexId, keyLabel);
      if (identity == null) {
        println("unknown identity");
        return;
      }
      if (Boolean.TRUE.equals(force)
          || confirm("Do you want to remove the identity " + identity, 3)) {
        long[] failedHandles = getSlot().destroyObjectsAndReturnFailedHandles(
                                    identity.getAllHandles());
        println(failedHandles == null || failedHandles.length == 0
            ? "deleted identity " + identity
            : "error deleting identity " + identity);
      }
    }
  }

  @Command(name = "object-exists-p11",
      description = "return whether objects exist in PKCS#11 device",
      mixinStandardHelpOptions = true)
  static class ObjectExistsP11Command extends P11SecurityCommand {

    @Option(names = "--id", description = "id (hex) of the object")
    private String id;

    @Option(names = "--label", description = "label of the object")
    private String label;

    @Override
    public void run() {
      try {
        byte[] idBytes = id == null ? null : Hex.decode(id);
        println(Boolean.toString(getSlot().objectExistsByIdLabel(idBytes, label)));
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "delete-objects-p11", description = "delete objects in PKCS#11 device",
      mixinStandardHelpOptions = true)
  static class DeleteObjectsP11Command extends P11SecurityCommand {

    @Option(names = {"--handle", "-h"}, split = ",", description = "object handles")
    private long[] handles;

    @Option(names = "--id", description = "id (hex) of the objects")
    private String id;

    @Option(names = "--label", description = "label of the objects")
    private String label;

    @Option(names = {"--force", "-f"}, description = "remove objects without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    public void run() {
      try {
        if (handles != null && handles.length > 0) {
          if (id != null || label != null) {
            throw new IllegalArgumentException("if handle is set, id and label must not be set");
          }
          if (Boolean.TRUE.equals(force)
              || confirm("Do you want to remove the PKCS#11 objects "
                  + Arrays.toString(handles), 3)) {
            long[] failedHandles = getSlot().destroyObjectsAndReturnFailedHandles(handles);
            if (failedHandles.length == 0) {
              println("deleted all " + handles.length + " objects");
            } else {
              println("deleted " + (handles.length - failedHandles.length) + " objects except "
                  + failedHandles.length + " objects: " + Arrays.toString(failedHandles));
            }
          }
        } else {
          if (id == null && label == null) {
            throw new IllegalArgumentException(
                "if handle is not set, at least one of id and label must be set");
          }
          if (Boolean.TRUE.equals(force)
              || confirm("Do you want to remove the PKCS#11 objects (id = "
                  + id + ", label = " + label + ")", 3)) {
            byte[] idBytes = id == null ? null : Hex.decode(id);
            int num = getSlot().destroyObjectsByIdLabel(idBytes, label);
            println("deleted " + num + " objects");
          }
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "delete-all-objects-p11", description = "delete all objects in PKCS#11 device",
      mixinStandardHelpOptions = true)
  static class DeleteAllObjectsP11Command extends P11SecurityCommand {

    @Override
    public void run() {
      try {
        String prompt = "!!!DANGEROUS OPERATION!!!, do you want to remove ALL PKCS#11 objects";
        if (confirm(prompt, 1) && confirm(prompt, 1) && confirm(prompt, 1)) {
          int num = getSlot().destroyAllObjects();
          println("Destroyed " + num + " objects!");
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "secretkey-p11", description = "generate secret key in PKCS#11 device",
      mixinStandardHelpOptions = true)
  static class SecretkeyP11Command extends P11KeyGenCommand {

    private static final Logger LOG = LoggerFactory.getLogger(SecretkeyP11Command.class);

    @Option(names = "--key-type", required = true, description = "secret key type")
    private String keyType;

    @Option(names = "--key-size", description = "keysize in bit")
    @Completion(FilePathCompleter.class)
    private Integer keysize;

    @Option(names = "--extern-if-gen-unsupported", description = "fallback to software generation")
    private Boolean createExternIfGenUnsupported = Boolean.FALSE;

    @Override
    public void run() {
      try {
        if (keysize != null && keysize % 8 != 0) {
          throw new IllegalArgumentException("keysize is not multiple of 8: " + keysize);
        }

        long p11KeyType;
        if ("AES".equalsIgnoreCase(keyType)) {
          p11KeyType = PKCS11T.CKK_AES;
        } else if ("DES3".equalsIgnoreCase(keyType)) {
          p11KeyType = PKCS11T.CKK_DES3;
          keysize = 192;
        } else if ("SM4".equalsIgnoreCase(keyType)) {
          p11KeyType = PKCS11T.CKK_VENDOR_SM4;
          keysize = 128;
        } else if ("GENERIC".equalsIgnoreCase(keyType)) {
          p11KeyType = PKCS11T.CKK_GENERIC_SECRET;
        } else {
          Long keyTypeL = PKCS11T.ckkNameToCode("CKK_" + keyType.replace('-', '_'));
          if (keyTypeL == null) {
            throw new IllegalArgumentException("invalid keyType " + keyType);
          }
          p11KeyType = keyTypeL;
        }

        if (keysize == null) {
          throw new IllegalArgumentException("key-size is not specified");
        }

        P11Slot slot = getSlot();
        PKCS11SecretKeySpec spec = getSecretKeyControl(p11KeyType);
        try {
          finalizeKey(keyType, slot.generateSecretKey(keysize, spec));
        } catch (TokenException ex) {
          if (!Boolean.TRUE.equals(createExternIfGenUnsupported)) {
            throw ex;
          }

          String msgPrefix = "could not generate secret key ";
          if (spec.id() != null) {
            msgPrefix += "id=" + Hex.encode(spec.id());
            if (spec.label() != null) {
              msgPrefix += " and ";
            }
          }
          if (spec.label() != null) {
            msgPrefix += "label=" + spec.label();
          }
          LOG.info("{}{}", msgPrefix, ex.getMessage());

          byte[] keyValue = new byte[keysize / 8];
          securities().securityFactory().random4Key().nextBytes(keyValue);
          PKCS11KeyId objId = slot.importSecretKey(keyValue, spec.keyType(p11KeyType));
          Arrays.fill(keyValue, (byte) 0);
          String msg = "generated in memory and imported " + keyType + " key " + objId;
          LOG.info(msg);
          println(msg);
        }
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  @Command(name = "import-secretkey-p11",
      description = "import secret key with given value in PKCS#11 device",
      mixinStandardHelpOptions = true)
  static class ImportSecretkeyP11Command extends P11KeyGenCommand {

    @Option(names = "--key-type", required = true, description = "keytype")
    @Completion(SecurityCompleters.SecretKeyTypeCompleter.class)
    private String keyType;

    @Option(names = "--keystore", required = true, description = "JCEKS keystore")
    @Completion(FilePathCompleter.class)
    private String keyOutFile;

    @Option(names = "--password", description = "password of the keystore file")
    private String passwordHint;

    @Override
    public void run() {
      try {
        long p11KeyType;
        if ("AES".equalsIgnoreCase(keyType)) {
          p11KeyType = PKCS11T.CKK_AES;
        } else if ("DES3".equalsIgnoreCase(keyType)) {
          p11KeyType = PKCS11T.CKK_DES3;
        } else if ("GENERIC".equalsIgnoreCase(keyType)) {
          p11KeyType = PKCS11T.CKK_GENERIC_SECRET;
        } else {
          throw new IllegalArgumentException("invalid keyType " + keyType);
        }

        KeyStore ks;
        char[] pwd = getPassword();
        try (InputStream ksStream = Files.newInputStream(
            Paths.get(IoUtil.expandFilepath(keyOutFile)))) {
          ks = KeyUtil.loadKeyStore("JCEKS", ksStream, pwd);
        }

        byte[] keyValue = null;
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
          String alias = aliases.nextElement();
          if (!ks.isKeyEntry(alias)) {
            continue;
          }
          Key key = ks.getKey(alias, pwd);
          if (key instanceof SecretKey) {
            keyValue = key.getEncoded();
            break;
          }
        }

        if (keyValue == null) {
          throw new IllegalArgumentException("keystore does not contain secret key");
        }

        PKCS11KeyId objId = getSlot().importSecretKey(keyValue, getSecretKeyControl(p11KeyType));
        println("imported " + keyType + " key " + objId);
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }

    private char[] getPassword() throws IOException, PasswordResolverException {
      return readPasswordIfNotSet("Enter the keystore password", passwordHint);
    }
  }

  @Command(name = "token-info-p11", description = "list objects in PKCS#11 device",
      mixinStandardHelpOptions = true)
  static class TokenInfoP11Command extends SecurityCommands.SecurityCommand {

    @Option(names = {"--verbose", "-v"}, description = "show object information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Option(names = "--module", description = "name of the PKCS#11 module")
    @Completion(SecurityCompleters.P11ModuleNameCompleter.class)
    private String moduleName = P11SecurityCommand.DEFAULT_P11MODULE_NAME;

    @Option(names = "--slot", description = "slot index")
    private Integer slotIndex;

    @Option(names = "--object", description = "object handle")
    private Long objectHandle;

    @Override
    public void run() {
      try {
        P11Module module = securities().p11CryptServiceFactory().getP11Module(moduleName);
        if (module == null) {
          throw new IllegalArgumentException("undefined module " + moduleName);
        }
        println("module: " + moduleName);
        println(module.description());

        List<P11SlotId> slots = module.slotIds();
        if (slotIndex == null) {
          int n = slots.size();
          println((n == 0 ? "no" : Integer.toString(n)) + (n == 1 ? " slot is configured"
              : " slots are configured"));
          for (P11SlotId slotId : slots) {
            println("\tslot[" + slotId.index() + "]: " + slotId.id());
          }
          return;
        }

        P11SlotId slotId = module.getSlotIdForIndex(slotIndex);
        P11Slot slot = module.getSlot(slotId);
        println("Details of slot " + slotId + ":");
        slot.showDetails(System.out, objectHandle, verbose);
        System.out.flush();
        System.out.println();
      } catch (Exception ex) {
        throw new RuntimeException(ex.getMessage(), ex);
      }
    }
  }

  abstract static class P11SecurityCommand extends SecurityCommands.SecurityCommand {

    protected static final String DEFAULT_P11MODULE_NAME =
        P11CryptServiceFactory.DEFAULT_P11MODULE_NAME;

    @Option(names = "--slot", description = "slot index")
    protected String slotIndex = "0";

    @Option(names = "--module", description = "name of the PKCS#11 module")
    @Completion(SecurityCompleters.P11ModuleNameCompleter.class)
    protected String moduleName = DEFAULT_P11MODULE_NAME;

    protected P11Slot getSlot() throws Exception {
      P11Module module = getP11Module(moduleName);
      P11SlotId slotId = module.getSlotIdForIndex(Integer.parseInt(slotIndex));
      return module.getSlot(slotId);
    }

    protected P11Module getP11Module(String name) throws Exception {
      P11Module module = securities().p11CryptServiceFactory().getP11Module(name);
      if (module == null) {
        throw new IllegalArgumentException("undefined module " + name);
      }
      return module;
    }

    protected PKCS11KeyId getIdentity(String hexId, String label) throws Exception {
      byte[] id = hexId == null ? null : Hex.decode(hexId);
      return getSlot().getKeyId(id, label);
    }

    protected boolean confirm(String prompt, int count) throws IOException {
      for (int i = 0; i < count; i++) {
        println(prompt + " [yes/no]");
        String answer = new BufferedReader(new InputStreamReader(System.in)).readLine();
        if (!"yes".equalsIgnoreCase(answer)) {
          return false;
        }
      }
      return true;
    }
  }

  abstract static class P11KeyGenCommand extends P11SecurityCommand {

    @Option(names = "--id", description = "id (hex) of the PKCS#11 objects")
    private String id;

    @Option(names = "--label", required = true, description = "label of the PKCS#11 objects")
    protected String label;

    @Option(names = {"--extractable", "-x"}, description = "whether the key is extractable")
    private String extractable;

    @Option(names = "--sensitive", description = "whether the key is sensitive")
    private String sensitive;

    @Option(names = "--key-usage", split = ",",
        description = "key usage of the private / secret key")
    @Completion(SecurityCompleters.P11KeyUsageCompleter.class)
    private List<String> keyusages;

    protected void finalizeKey(String keySpec, PKCS11KeyId keyId) {
      Args.notNull(keyId, "keyId");
      println("generated " + keySpec + " key " + keyId + " on slot " + slotIndex);
    }

    protected NewKeyControl getControl() {
      byte[] id0 = id == null ? null : Hex.decode(id);
      NewKeyControl control = new NewKeyControl(id0, label);
      if (StringUtil.isNotBlank(extractable)) {
        control.setExtractable(parseBoolean(extractable, "extractable"));
      }
      if (StringUtil.isNotBlank(sensitive)) {
        control.setSensitive(parseBoolean(sensitive, "sensitive"));
      }
      if (CollectionUtil.isNotEmpty(keyusages)) {
        control.setUsages(parseUsages(keyusages));
      }
      return control;
    }

    protected PKCS11SecretKeySpec getSecretKeyControl(long keyType) {
      NewKeyControl control = getControl();
      PKCS11SecretKeySpec spec = new PKCS11SecretKeySpec()
          .token(true).keyType(keyType).id(control.id()).label(control.label())
          .extractable(control.extractable()).sensitive(control.sensitive());
      Set<NewKeyControl.P11KeyUsage> usages = control.usages();
      if (usages == null) {
        if (keyType == PKCS11T.CKK_GENERIC_SECRET
            || keyType == PKCS11T.CKK_SHA_1_HMAC
            || keyType == PKCS11T.CKK_SHA224_HMAC
            || keyType == PKCS11T.CKK_SHA3_224_HMAC
            || keyType == PKCS11T.CKK_SHA256_HMAC
            || keyType == PKCS11T.CKK_SHA3_256_HMAC
            || keyType == PKCS11T.CKK_SHA384_HMAC
            || keyType == PKCS11T.CKK_SHA3_384_HMAC
            || keyType == PKCS11T.CKK_SHA512_HMAC
            || keyType == PKCS11T.CKK_SHA3_512_HMAC) {
          spec.sign(true).verify(true);
        } else {
          spec.sign(true).verify(true).encrypt(true).decrypt(true);
        }
      } else {
        for (NewKeyControl.P11KeyUsage usage : usages) {
          switch (usage) {
            case ENCRYPT:
              spec.encrypt(true);
              break;
            case DECRYPT:
              spec.decrypt(true);
              break;
            case DERIVE:
              spec.derive(true);
              break;
            case SIGN:
              spec.sign(true);
              break;
            case VERIFY:
              spec.verify(true);
              break;
            case WRAP:
              spec.wrap(true);
              break;
            case UNWRAP:
              spec.unwrap(true);
              break;
            default:
              break;
          }
        }
      }
      return spec;
    }

    private static boolean parseBoolean(String value, String name) {
      if (StringUtil.orEqualsIgnoreCase(value, "yes", "true")) {
        return true;
      } else if (StringUtil.orEqualsIgnoreCase(value, "no", "false")) {
        return false;
      } else {
        throw new IllegalArgumentException("invalid " + name + ": " + value);
      }
    }

    private static Set<NewKeyControl.P11KeyUsage> parseUsages(List<String> usages) {
      Set<NewKeyControl.P11KeyUsage> set = new HashSet<>();
      for (String usage : usages) {
        set.add(NewKeyControl.P11KeyUsage.valueOf(
            usage.trim().replace('-', '_').toUpperCase()));
      }
      return set;
    }
  }
}
