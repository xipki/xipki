// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.shell;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.password.PasswordResolverException;
import org.xipki.pkcs11.wrapper.PKCS11KeyId;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.*;
import org.xipki.security.pkcs11.*;
import org.xipki.security.pkcs11.P11Slot.P11NewKeyControl;
import org.xipki.security.shell.Actions.CsrGenAction;
import org.xipki.security.shell.Actions.SecurityAction;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.KeyUtil;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.*;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import static org.xipki.pkcs11.wrapper.PKCS11Constants.*;

/**
 * Actions for PKCS#11 security.
 *
 * @author Lijun Liao (xipki)
 */

public class P11Actions {

  @Command(scope = "xi", name = "csr-p11", description = "generate CSR request with PKCS#11 device")
  @Service
  public static class CsrP11 extends CsrGenAction {

    @Option(name = "--slot", description = "slot index")
    private String slotIndex = "0"; // use String instead int so that the default value 0 will be shown in the help.

    @Option(name = "--id", description = "id (hex) of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    private String id;

    @Option(name = "--label", description = "label of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    private String label;

    @Option(name = "--module", description = "name of the PKCS#11 module")
    @Completion(SecurityCompleters.P11ModuleNameCompleter.class)
    private String moduleName = "default";

    @Override
    protected ConcurrentContentSigner getSigner() throws Exception {
      SignatureAlgoControl signatureAlgoControl = getSignatureAlgoControl();

      byte[] idBytes = null;
      if (id != null) {
        idBytes = Hex.decode(id);
      }

      SignerConf conf = getPkcs11SignerConf(moduleName, Integer.parseInt(slotIndex), label,
          idBytes, 1, HashAlgo.getInstance(hashAlgo), signatureAlgoControl);
      return securityFactory.createSigner("PKCS11", conf, (X509Cert[]) null);
    }

    public static SignerConf getPkcs11SignerConf(
        String pkcs11ModuleName, int slotIndex, String keyLabel, byte[] keyId, int parallelism,
        HashAlgo hashAlgo, SignatureAlgoControl signatureAlgoControl) {
      Args.positive(parallelism, "parallelism");
      Args.notNull(hashAlgo, "hashAlgo");

      if (keyId == null && keyLabel == null) {
        throw new IllegalArgumentException("at least one of keyId and keyLabel may not be null");
      }

      ConfPairs conf = new ConfPairs();
      conf.putPair("parallelism", Integer.toString(parallelism));

      if (pkcs11ModuleName != null && pkcs11ModuleName.length() > 0) {
        conf.putPair("module", pkcs11ModuleName);
      }

      conf.putPair("slot", Integer.toString(slotIndex));

      if (keyId != null) {
        conf.putPair("key-id", Hex.encode(keyId));
      }

      if (keyLabel != null) {
        conf.putPair("key-label", keyLabel);
      }

      return new SignerConf(conf.getEncoded(), hashAlgo, signatureAlgoControl);
    } // method getPkcs11SignerConf

  } // class CsrP11

  @Command(scope = "xi", name = "dsa-p11", description = "generate DSA keypair in PKCS#11 device")
  @Service
  public static class Dsa11 extends P11KeyGenAction {

    @Option(name = "--plen", description = "bit length of the prime")
    private Integer plen = 2048;

    @Option(name = "--qlen", description = "bit length of the sub-prime")
    private Integer qlen;

    @Override
    protected Object execute0() throws Exception {
      if (plen % 1024 != 0) {
        throw new IllegalCmdParamException("plen is not multiple of 1024: " + plen);
      }

      if (qlen == null) {
        qlen = (plen <= 1024) ? 160 : ((plen <= 2048) ? 224 : 256);
      }

      P11Slot slot = getSlot();
      finalize("DSA", slot.generateDSAKeypair(plen, qlen, getControl()));
      return null;
    }

  } // method Dsa11

  @Command(scope = "xi", name = "ec-p11", description = "generate EC keypair in PKCS#11 device")
  @Service
  public static class EcP11 extends P11KeyGenAction {

    @Option(name = "--curve", description = "EC curve name")
    @Completion(Completers.ECCurveNameCompleter.class)
    private String curveName = "secp256r1";

    @Override
    protected Object execute0() throws Exception {
      P11Slot slot = getSlot();
      P11NewKeyControl control = getControl();

      ASN1ObjectIdentifier curveOid = EdECConstants.getCurveOid(curveName);
      if (curveOid == null) {
        curveOid = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveName);
      }

      if (curveOid == null) {
        throw new Exception("unknown curve " + curveName);
      }

      finalize("EC", slot.generateECKeypair(curveOid, control));
      return null;
    }

  } // class EcP11

  @Command(scope = "xi", name = "delete-key-p11", description = "delete key in PKCS#11 device")
  @Service
  public static class DeleteKeyP11 extends P11SecurityAction {

    @Option(name = "--id", description = "id (hex) of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    protected String id;

    @Option(name = "--label", description = "label of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    protected String label;

    @Option(name = "--force", aliases = "-f", description = "remove identifies without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      P11Slot slot = getSlot();
      P11Key identity = getIdentity(id, label);
      if (identity == null) {
        println("unknown identity");
        return null;
      }

      if (force || confirm("Do you want to remove the identity " + identity.getKeyId(), 3)) {
        identity.destroy();
        println("deleted identity " + identity.getKeyId());
      }
      return null;
    }

  } // class DeleteKeyP11

  @Command(scope = "xi", name = "key-exists-p11", description = "return whether keys exist in PKCS#11 device")
  @Service
  public static class KeyExistsP11 extends P11SecurityAction {

    @Option(name = "--id", description = "id (hex) of the private key in the PKCS#11 device\n"
                    + "either keyId or keyLabel must be specified")
    protected String id;

    @Option(name = "--label", description = "label of the private key in the PKCS#11 device\n"
                    + "either keyId or keyLabel must be specified")
    protected String label;

    @Override
    protected Object execute0() throws Exception {
      return null != getIdentity(id, label);
    }

  } // class KeyExistsP11

  public abstract static class P11KeyGenAction extends P11SecurityAction {

    @Option(name = "--id", description = "id (hex) of the PKCS#11 objects")
    private String id;

    @Option(name = "--label", required = true, description = "label of the PKCS#11 objects")
    protected String label;

    @Option(name = "--extractable", aliases = {"-x"},
        description = "whether the key is extractable, valid values are yes|no|true|false")
    private String extractable;

    @Option(name = "--sensitive", description = "whether the key is sensitive, valid values are yes|no|true|false")
    private String sensitive;

    @Option(name = "--key-usage", multiValued = true, description = "key usage of the private key")
    @Completion(SecurityCompleters.P11KeyUsageCompleter.class)
    private List<String> keyusages;

    protected void finalize(String keyType, PKCS11KeyId keyId) {
      Args.notNull(keyId, "keyId");
      println("generated " + keyType + " key " + keyId + " on slot " + slotIndex);
    }

    protected P11NewKeyControl getControl() throws IllegalCmdParamException {
      byte[] id0 = (id == null) ? null : Hex.decode(id);
      P11NewKeyControl control = new P11NewKeyControl(id0, label);
      if (StringUtil.isNotBlank(extractable)) {
        control.setExtractable(isEnabled(extractable, false, "extractable"));
      }
      if (StringUtil.isNotBlank(sensitive)) {
        control.setSensitive(isEnabled(sensitive, false, "sensitive"));
      }
      if (CollectionUtil.isNotEmpty(keyusages)) {
        control.setUsages(SecurityCompleters.P11KeyUsageCompleter.parseUsages(keyusages));
      }

      return control;
    }

  } // class P11KeyGenAction

  @Command(scope = "xi", name = "delete-objects-p11", description = "delete objects in PKCS#11 device")
  @Service
  public static class DeleteObjectsP11 extends P11SecurityAction {

    @Option(name = "--handle", aliases = "-h", multiValued = true,
        description = "Object handle, if specified, id and label must not be set")
    private long[] handles;

    @Option(name = "--id", description = "id (hex) of the objects in the PKCS#11 device\n"
            + "at least one of id and label must be specified (if handle is not set).")
    private String id;

    @Option(name = "--label", description = "label of the objects in the PKCS#11 device\n"
            + "at least one of id and label must be specified (if handle is not set).")
    private String label;

    @Option(name = "--force", aliases = "-f", description = "remove identifies without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      if (handles != null && handles.length > 0) {
        if (id != null || label != null) {
          throw new IllegalCmdParamException("If handle is set, id an label must not be set.");
        }

        if (force || confirm("Do you want to remove the PKCS#11 objects " + Arrays.toString(handles), 3)) {
          P11Slot slot = getSlot();
          long[] failedHandles = slot.destroyObjectsByHandle(handles);
          if (failedHandles.length == 0) {
            println("deleted all " + handles.length + " objects");
          } else {
            println("deleted " + (handles.length - failedHandles.length) + " objects except " +
                failedHandles.length + " objects: " + Arrays.toString(failedHandles));
          }
        }

      } else {
        if (id == null && label == null) {
          throw new IllegalCmdParamException("If handle is not set, at least one of id and label must be set.");
        }

        if (force || confirm("Do you want to remove the PKCS#11 objects (id = " + id
            + ", label = " + label + ")", 3)) {
          P11Slot slot = getSlot();
          byte[] idBytes = null;

          int num;
          if (id != null) {
            idBytes = Hex.decode(id);
            if (label == null) {
              num = slot.destroyObjectsById(idBytes);
            } else {
              num = slot.destroyObjectsByIdLabel(idBytes, label);
            }
          } else {
            num = slot.destroyObjectsByLabel(label);
          }
          println("deleted " + num + " objects");
        }
      }
      return null;
    }

  } // class DeleteObjectsP11

  @Command(scope = "xi", name = "delete-all-objects-p11", description = "delete all objects in PKCS#11 device")
  @Service
  public static class DeleteAllObjectsP11 extends P11SecurityAction {

    @Override
    protected Object execute0() throws Exception {
      String prompt = "!!!DANGEROUS OPERATION!!!, do you want to remove ALL PKCS#11 objects";
      // this is not a bug to require 3 confirmations.
      if (confirm(prompt, 1)) {
        if (confirm(prompt, 1)) {
          if (confirm(prompt, 1)) {
            P11Slot slot = getSlot();
            int num = slot.destroyAllObjects();
            System.out.println("Destroyed " + num + " objects!");
          }
        }
      }
      return null;
    }

  } // class DeleteAllObjectsP11

  @Command(scope = "xi", name = "rsa-p11", description = "generate RSA keypair in PKCS#11 device")
  @Service
  public static class RsaP11 extends P11KeyGenAction {

    @Option(name = "--key-size", description = "keysize in bit")
    private Integer keysize = 2048;

    @Option(name = "-e", description = "public exponent")
    private String publicExponent = Actions.TEXT_F4;

    @Override
    protected Object execute0() throws Exception {
      if (keysize % 1024 != 0) {
        throw new IllegalCmdParamException("keysize is not multiple of 1024: " + keysize);
      }

      P11Slot slot = getSlot();
      finalize("RSA", slot.generateRSAKeypair(keysize, toBigInt(publicExponent), getControl()));
      return null;
    }

  } // class RsaP11

  @Command(scope = "xi", name = "secretkey-p11", description = "generate secret key in PKCS#11 device")
  @Service
  public static class SecretkeyP11 extends P11KeyGenAction {

    private static final Logger LOG = LoggerFactory.getLogger(SecretkeyP11.class);

    @Option(name = "--key-type", required = true,
        description = "keytype, current only AES, DES3 and GENERIC are supported")
    @Completion(SecurityCompleters.SecretKeyTypeCompleter.class)
    private String keyType;

    @Option(name = "--key-size", description = "keysize in bit")
    private Integer keysize;

    @Option(name = "--extern-if-gen-unsupported",
        description = "If set, if the generation mechanism is not supported by the PKCS#11 "
            + "device, create in memory and then import it to the device")
    private Boolean createExternIfGenUnsupported = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      if (keysize != null && keysize % 8 != 0) {
        throw new IllegalCmdParamException("keysize is not multiple of 8: " + keysize);
      }

      long p11KeyType;
      if ("AES".equalsIgnoreCase(keyType)) {
        p11KeyType = CKK_AES;
      } else if ("DES3".equalsIgnoreCase(keyType)) {
        p11KeyType = CKK_DES3;
        keysize = 192;
      } else if ("GENERIC".equalsIgnoreCase(keyType)) {
        p11KeyType = CKK_GENERIC_SECRET;
      } else {
        throw new IllegalCmdParamException("invalid keyType " + keyType);
      }

      if (keysize == null) {
        throw new IllegalCmdParamException("key-size is not specified");
      }

      P11Slot slot = getSlot();
      P11NewKeyControl control = getControl();

      try {
        finalize(keyType, slot.generateSecretKey(p11KeyType, keysize, control));
      } catch (TokenException ex) {
        if (!createExternIfGenUnsupported) {
          throw ex;
        }

        String msgPrefix = "could not generate secret key ";
        if (control.getId() != null) {
          msgPrefix += "id=" + Hex.encode(control.getId());

          if (control.getLabel() != null) {
            msgPrefix += " and ";
          }
        }

        if (control.getLabel() != null) {
          msgPrefix += "label=" + control.getLabel();
        }

        if (LOG.isInfoEnabled()) {
          LOG.info(msgPrefix + ex.getMessage());
        }

        if (LOG.isDebugEnabled()) {
          LOG.debug(msgPrefix, ex);
        }

        byte[] keyValue = new byte[keysize / 8];
        securityFactory.getRandom4Key().nextBytes(keyValue);

        PKCS11KeyId objId = slot.importSecretKey(p11KeyType, keyValue, control);
        Arrays.fill(keyValue, (byte) 0); // clear the memory
        String msg = "generated in memory and imported " + keyType + " key " + objId;
        if (LOG.isInfoEnabled()) {
          LOG.info(msg);
        }
        println(msg);
      }

      return null;
    } // method execute0

  } // class SecretkeyP11

  @Command(scope = "xi", name = "import-secretkey-p11",
      description = "import secret key with given value in PKCS#11 device")
  @Service
  public static class ImportSecretkeyP11 extends P11KeyGenAction {

    @Option(name = "--key-type", required = true,
        description = "keytype, current only AES, DES3 and GENERIC are supported")
    @Completion(SecurityCompleters.SecretKeyTypeCompleter.class)
    private String keyType;

    @Option(name = "--keystore", required = true, description = "JCEKS keystore from which the key is imported")
    @Completion(FileCompleter.class)
    private String keyOutFile;

    @Option(name = "--password", description = "password of the keystore file, as plaintext or PBE-encrypted.")
    private String passwordHint;

    @Override
    protected Object execute0() throws Exception {
      long p11KeyType;
      if ("AES".equalsIgnoreCase(keyType)) {
        p11KeyType = CKK_AES;
      } else if ("DES3".equalsIgnoreCase(keyType)) {
        p11KeyType = CKK_DES3;
      } else if ("GENERIC".equalsIgnoreCase(keyType)) {
        p11KeyType = CKK_GENERIC_SECRET;
      } else {
        throw new IllegalCmdParamException("invalid keyType " + keyType);
      }

      KeyStore ks = KeyUtil.getInKeyStore("JCEKS");
      InputStream ksStream = Files.newInputStream(Paths.get(IoUtil.expandFilepath(keyOutFile)));
      char[] pwd = getPassword();
      try {
        ks.load(ksStream, pwd);
      } finally {
        ksStream.close();
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
        throw new IllegalCmdParamException("keystore does not contain secret key");
      }

      P11Slot slot = getSlot();
      PKCS11KeyId objId = slot.importSecretKey(p11KeyType, keyValue, getControl());
      println("imported " + keyType + " key " + objId);
      return null;
    } // method execute0

    protected char[] getPassword() throws IOException, PasswordResolverException {
      char[] pwdInChar = readPasswordIfNotSet("Enter the keystore password", passwordHint);
      if (pwdInChar != null) {
        passwordHint = new String(pwdInChar);
      }
      return pwdInChar;
    }

  } // class ImportSecretkeyP11

  public abstract static class P11SecurityAction extends SecurityAction {

    protected static final String DEFAULT_P11MODULE_NAME = P11CryptServiceFactory.DEFAULT_P11MODULE_NAME;

    @Option(name = "--slot", description = "slot index")
    protected String slotIndex = "0"; // use String instead int so that the default value 0 will be shown in the help.

    @Option(name = "--module", description = "name of the PKCS#11 module")
    @Completion(SecurityCompleters.P11ModuleNameCompleter.class)
    protected String moduleName = DEFAULT_P11MODULE_NAME;

    @Reference (optional = true)
    protected P11CryptServiceFactory p11CryptServiceFactory;

    protected P11Slot getSlot() throws XiSecurityException, TokenException, IllegalCmdParamException {
      P11Module module = getP11Module(moduleName);
      P11SlotId slotId = module.getSlotIdForIndex(Integer.parseInt(slotIndex));
      return module.getSlot(slotId);
    }

    protected P11Module getP11Module(String moduleName)
        throws XiSecurityException, TokenException, IllegalCmdParamException {
      P11CryptService p11Service = p11CryptServiceFactory.getP11CryptService(moduleName);
      if (p11Service == null) {
        throw new IllegalCmdParamException("undefined module " + moduleName);
      }
      return p11Service.getModule();
    }

    public P11Key getIdentity(String hexId, String label)
        throws IllegalCmdParamException, XiSecurityException, TokenException {
      P11Slot slot = getSlot();
      byte[] id = hexId == null ? null : Hex.decode(hexId);
      return slot.getKey(id, label);
    }

  } // class P11SecurityAction

  @Command(scope = "xi", name = "sm2-p11", description = "generate SM2 (curve sm2p256v1) keypair in PKCS#11 device")
  @Service
  public static class Sm2P11 extends P11KeyGenAction {

    @Override
    protected Object execute0() throws Exception {
      P11Slot slot = getSlot();
      finalize("SM2", slot.generateSM2Keypair(getControl()));
      return null;
    }

  } // class Sm2P11

  @Command(scope = "xi", name = "token-info-p11", description = "list objects in PKCS#11 device")
  @Service
  public static class TokenInfoP11 extends SecurityAction {

    @Option(name = "--verbose", aliases = "-v", description = "show object information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Option(name = "--module", description = "name of the PKCS#11 module.")
    @Completion(SecurityCompleters.P11ModuleNameCompleter.class)
    private String moduleName = P11SecurityAction.DEFAULT_P11MODULE_NAME;

    @Option(name = "--slot", description = "slot index")
    private Integer slotIndex;

    @Option(name = "--object", description = "object handle")
    private Long objectHandle;

    @Reference (optional = true)
    protected P11CryptServiceFactory p11CryptServiceFactory;

    @Override
    protected Object execute0() throws Exception {
      P11CryptService p11Service = p11CryptServiceFactory.getP11CryptService(moduleName);
      if (p11Service == null) {
        throw new IllegalCmdParamException("undefined module " + moduleName);
      }

      P11Module module = p11Service.getModule();
      println("module: " + moduleName);
      println(module.getDescription());

      List<P11SlotId> slots = module.getSlotIds();
      if (slotIndex == null) {
        output(slots);
        return null;
      }

      P11SlotId slotId = module.getSlotIdForIndex(slotIndex);
      P11Slot slot = module.getSlot(slotId);
      println("Details of slot " + slotId + ":");
      slot.showDetails(System.out, objectHandle, verbose);

      System.out.flush();
      System.out.println();
      return null;
    }

    private void output(List<P11SlotId> slots) {
      // list all slots
      final int n = slots.size();

      if (n == 0 || n == 1) {
        String numText = (n == 0) ? "no" : "1";
        println(numText + " slot is configured");
      } else {
        println(n + " slots are configured");
      }

      for (P11SlotId slotId : slots) {
        println("\tslot[" + slotId.getIndex() + "]: " + slotId.getId());
      }
    }

  } // class TokenInfoP11

}
