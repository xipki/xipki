/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.security.shell;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.SecretKey;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.security.ConcurrentContentSigner;
import org.xipki.security.EdECConstants;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignatureAlgoControl;
import org.xipki.security.SignerConf;
import org.xipki.security.XiSecurityConstants;
import org.xipki.security.XiSecurityException;
import org.xipki.security.pkcs11.P11CryptService;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11Slot.P11NewKeyControl;
import org.xipki.security.pkcs11.P11Slot.P11NewObjectControl;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.security.pkcs11.P11TokenException;
import org.xipki.security.pkcs11.P11UnsupportedMechanismException;
import org.xipki.security.pkcs11.provider.XiSM2ParameterSpec;
import org.xipki.security.shell.Actions.CsrGenAction;
import org.xipki.security.shell.Actions.SecurityAction;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.Hex;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

import iaik.pkcs.pkcs11.constants.PKCS11Constants;

/**
 * Actions for PKCS#11 security.
 *
 * @author Lijun Liao
 */

public class P11Actions {

  @Command(scope = "xi", name = "add-cert-p11", description = "add certificate to PKCS#11 device")
  @Service
  public static class AddCertP11 extends P11SecurityAction {

    @Option(name = "--id", description = "id of the PKCS#11 objects")
    private String hexId;

    @Option(name = "--label", description = "label of the PKCS#11 objects.")
    protected String label;

    @Option(name = "--cert", required = true, description = "certificate file")
    @Completion(FileCompleter.class)
    private String certFile;

    @Override
    protected Object execute0() throws Exception {
      byte[] id = (hexId == null) ? null : Hex.decode(hexId);
      X509Certificate cert = X509Util.parseCert(new File(certFile));
      if (label == null) {
        label = X509Util.getCommonName(cert.getSubjectX500Principal());
      }
      P11NewObjectControl control = new P11NewObjectControl(id, label);
      P11Slot slot = getSlot();
      P11ObjectIdentifier objectId = slot.addCert(cert, control);
      println("added certificate under " + objectId);
      return null;
    }

  }

  @Command(scope = "xi", name = "delete-cert-p11",
      description = "remove certificate from PKCS#11 device")
  @Service
  public static class DeleteCertP11 extends P11SecurityAction {

    @Option(name = "--id", required = true,
        description = "id of the certificate in the PKCS#11 device")
    private String id;

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      if (force || confirm("Do you want to remove PKCS#11 certificate object with id " + id, 3)) {
        P11Slot slot = getSlot();
        P11ObjectIdentifier objectId = slot.getObjectId(Hex.decode(id), null);
        if (objectId == null) {
          println("unkown certificates");
        } else {
          slot.removeCerts(objectId);
          println("deleted certificates");
        }
      }

      return null;
    }

  }

  @Command(scope = "xi", name = "export-cert-p11",
      description = "export certificate from PKCS#11 device")
  @Service
  public static class ExportCertP11 extends P11SecurityAction {

    @Option(name = "--id",
        description = "id of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    protected String id;

    @Option(name = "--label",
        description = "label of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    protected String label;

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outFile;

    @Override
    protected Object execute0() throws Exception {
      P11Slot slot = getSlot();
      P11ObjectIdentifier objIdentifier = getObjectIdentifier(id, label);
      X509Certificate cert = slot.exportCert(objIdentifier);
      if (cert == null) {
        throw new CmdFailure("could not export certificate " + objIdentifier);
      }
      saveVerbose("saved certificate to file", outFile, encodeCert(cert.getEncoded(), outform));
      return null;
    }

  }

  @Command(scope = "xi", name = "update-cert-p11",
      description = "update certificate in PKCS#11 device")
  @Service
  public static class UpdateCertP11 extends P11SecurityAction {

    @Option(name = "--id",
        description = "id of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    protected String id;

    @Option(name = "--label",
        description = "label of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    protected String label;

    @Option(name = "--cert", required = true, description = "certificate file")
    @Completion(FileCompleter.class)
    private String certFile;

    @Override
    protected Object execute0() throws Exception {
      P11Slot slot = getSlot();
      P11ObjectIdentifier objIdentifier = getObjectIdentifier(id, label);
      X509Certificate newCert = X509Util.parseCert(new File(certFile));
      slot.updateCertificate(objIdentifier, newCert);
      println("updated certificate");
      return null;
    }

  }

  @Command(scope = "xi", name = "csr-p11", description = "generate CSR request with PKCS#11 device")
  @Service
  public static class CsrP11 extends CsrGenAction {

    @Option(name = "--slot", required = true, description = "slot index")
    private Integer slotIndex;

    @Option(name = "--id",
        description = "id of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    private String id;

    @Option(name = "--label",
        description = "label of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    private String label;

    @Option(name = "--module",
        description = "name of the PKCS#11 module")
    @Completion(SecurityCompleters.P11ModuleNameCompleter.class)
    private String moduleName = "default";

    @Override
    protected ConcurrentContentSigner getSigner(SignatureAlgoControl signatureAlgoControl)
        throws Exception {
      Args.notNull(signatureAlgoControl, "signatureAlgoControl");

      byte[] idBytes = null;
      if (id != null) {
        idBytes = Hex.decode(id);
      }

      SignerConf conf = getPkcs11SignerConf(moduleName, slotIndex, label,
          idBytes, 1, HashAlgo.getNonNullInstance(hashAlgo), signatureAlgoControl);
      return securityFactory.createSigner("PKCS11", conf, (X509Certificate[]) null);
    }

    public static SignerConf getPkcs11SignerConf(String pkcs11ModuleName, Integer slotIndex,
        String keyLabel, byte[] keyId, int parallelism, HashAlgo hashAlgo,
        SignatureAlgoControl signatureAlgoControl) {
      Args.positive(parallelism, "parallelism");
      Args.notNull(hashAlgo, "hashAlgo");

      if (slotIndex == null) {
        throw new IllegalArgumentException("slotIndex may not be null");
      }

      if (keyId == null && keyLabel == null) {
        throw new IllegalArgumentException("at least one of keyId and keyLabel may not be null");
      }

      ConfPairs conf = new ConfPairs();
      conf.putPair("parallelism", Integer.toString(parallelism));

      if (pkcs11ModuleName != null && pkcs11ModuleName.length() > 0) {
        conf.putPair("module", pkcs11ModuleName);
      }

      if (slotIndex != null) {
        conf.putPair("slot", slotIndex.toString());
      }

      if (keyId != null) {
        conf.putPair("key-id", Hex.encode(keyId));
      }

      if (keyLabel != null) {
        conf.putPair("key-label", keyLabel);
      }

      return new SignerConf(conf.getEncoded(), hashAlgo, signatureAlgoControl);
    }

  }

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
        if (plen <= 1024) {
          qlen = 160;
        } else if (plen <= 2048) {
          qlen = 224;
        } else {
          qlen = 256;
        }
      }

      P11Slot slot = getSlot();
      P11IdentityId identityId = slot.generateDSAKeypair(plen, qlen, getControl());
      finalize("DSA", identityId);
      return null;
    }

  }

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

      P11IdentityId identityId;
      if (EdECConstants.isEdwardsCurve(curveName)) {
        identityId = slot.generateECEdwardsKeypair(curveName, control);
      } else if (EdECConstants.isMontgemoryCurve(curveName)) {
        identityId = slot.generateECMontgomeryKeypair(curveName, control);
      } else {
        identityId = slot.generateECKeypair(curveName, control);
      }

      finalize("EC", identityId);
      return null;
    }

  }

  @Command(scope = "xi", name = "delete-key-p11",
      description = "delete key and cert in PKCS#11 device")
  @Service
  public static class DeleteKeyP11 extends P11SecurityAction {

    @Option(name = "--id",
        description = "id of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    protected String id;

    @Option(name = "--label",
        description = "label of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    protected String label;

    @Option(name = "--force", aliases = "-f", description = "remove identifies without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      P11Slot slot = getSlot();
      P11ObjectIdentifier keyId = getObjectIdentifier(id, label);
      if (keyId == null) {
        println("unkown identity");
        return null;
      }

      if (force || confirm("Do you want to remove the identity " + keyId, 3)) {
        slot.removeIdentityByKeyId(keyId);
        println("deleted identity " + keyId);
      }
      return null;
    }

  }

  public abstract static class P11KeyGenAction extends P11SecurityAction {

    @Option(name = "--id", description = "id of the PKCS#11 objects")
    private String hexId;

    @Option(name = "--label", required = true, description = "label of the PKCS#11 objects")
    protected String label;

    @Option(name = "--extractable", aliases = {"-x"},
        description = "whether the key is extractable, valid values are yes|no|true|false")
    private String extractable;

    @Option(name = "--sensitive",
        description = "whether the key is sensitive, valid values are yes|no|true|false")
    private String sensitive;

    @Option(name = "--key-usage", multiValued = true,
        description = "key usage of the private key")
    @Completion(SecurityCompleters.P11KeyUsageCompleter.class)
    private List<String> keyusages;

    protected void finalize(String keyType, P11IdentityId identityId) throws Exception {
      Args.notNull(identityId, "identityId");
      println("generated " + keyType + " key \"" + identityId + "\"");
    }

    protected P11NewKeyControl getControl() throws IllegalCmdParamException {
      byte[] id = (hexId == null) ? null : Hex.decode(hexId);
      P11NewKeyControl control = new P11NewKeyControl(id, label);
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

  }

  @Command(scope = "xi", name = "delete-objects-p11",
      description = "delete objects in PKCS#11 device")
  @Service
  public static class DeleteObjectsP11 extends P11SecurityAction {

    @Option(name = "--id",
        description = "id (hex) of the objects in the PKCS#11 device\n"
            + "at least one of id and label must be specified")
    private String id;

    @Option(name = "--label",
        description = "label of the objects in the PKCS#11 device\n"
            + "at least one of id and label must be specified")
    private String label;

    @Option(name = "--force", aliases = "-f", description = "remove identifies without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      if (force || confirm("Do you want to remove the PKCS#11 objects (id = " + id
          + ", label = " + label + ")", 3)) {
        P11Slot slot = getSlot();
        byte[] idBytes = null;
        if (id != null) {
          idBytes = Hex.decode(id);
        }
        int num = slot.removeObjects(idBytes, label);
        println("deleted " + num + " objects");
      }
      return null;
    }

  }

  @Command(scope = "xi", name = "p11prov-sm2-test",
      description = "test the SM2 implementation of Xipki PKCS#11 JCA/JCE provider")
  @Service
  public static class P11provSm2Test extends P11SecurityAction {

    @Option(name = "--id",
        description = "id of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    protected String id;

    @Option(name = "--label",
        description = "label of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    protected String label;

    @Option(name = "--verbose", aliases = "-v",
        description = "show object information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Option(name = "--ida", description = "IDA (ID user A)")
    protected String ida;

    @Override
    protected Object execute0() throws Exception {
      KeyStore ks = KeyStore.getInstance("PKCS11", XiSecurityConstants.PROVIDER_NAME_XIPKI);
      ks.load(null, null);
      if (verbose.booleanValue()) {
        println("available aliases:");
        Enumeration<?> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
          String alias2 = (String) aliases.nextElement();
          println("    " + alias2);
        }
      }

      String alias = getAlias();
      println("alias: " + alias);
      PrivateKey key = (PrivateKey) ks.getKey(alias, null);
      if (key == null) {
        println("could not find key with alias '" + alias + "'");
        return null;
      }

      Certificate cert = ks.getCertificate(alias);
      if (cert == null) {
        println("could not find certificate to verify signature");
        return null;
      }

      String sigAlgo = "SM3withSM2";
      println("signature algorithm: " + sigAlgo);
      Signature sig = Signature.getInstance(sigAlgo, XiSecurityConstants.PROVIDER_NAME_XIPKI);

      if (StringUtil.isNotBlank(ida)) {
        sig.setParameter(new XiSM2ParameterSpec(StringUtil.toUtf8Bytes(ida)));
      }

      sig.initSign(key);

      byte[] data = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
      sig.update(data);
      byte[] signature = sig.sign(); // CHECKSTYLE:SKIP
      println("signature created successfully");

      Signature ver = Signature.getInstance(sigAlgo, "BC");
      if (StringUtil.isNotBlank(ida)) {
        ver.setParameter(new SM2ParameterSpec(StringUtil.toUtf8Bytes(ida)));
      }

      ver.initVerify(cert.getPublicKey());
      ver.update(data);
      boolean valid = ver.verify(signature);
      println("signature valid: " + valid);
      return null;
    }

    private String getAlias() {
      if (label != null) {
        return StringUtil.concat(moduleName, "#slotindex-", slotIndex.toString(),
            "#keylabel-", label);
      } else {
        return StringUtil.concat(moduleName, "#slotindex-", slotIndex.toString(),
            "#keyid-", id.toLowerCase());
      }
    }

  }

  @Command(scope = "xi", name = "p11prov-test",
      description = "test the Xipki PKCS#11 JCA/JCE provider")
  @Service
  public static class P11provTest extends P11SecurityAction {

    @Option(name = "--id",
        description = "id of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    protected String id;

    @Option(name = "--label",
        description = "label of the private key in the PKCS#11 device\n"
            + "either keyId or keyLabel must be specified")
    protected String label;

    @Option(name = "--verbose", aliases = "-v", description = "show object information verbosely")
    private Boolean verbose = Boolean.FALSE;

    @Option(name = "--hash", description = "hash algorithm name")
    @Completion(Completers.HashAlgCompleter.class)
    protected String hashAlgo = "SHA256";

    @Option(name = "--rsa-mgf1",
        description = "whether to use the RSAPSS MGF1 for the POPO computation\n"
            + "(only applied to RSA key)")
    private Boolean rsaMgf1 = Boolean.FALSE;

    @Option(name = "--dsa-plain",
        description = "whether to use the Plain DSA for the POPO computation\n"
            + "(only applied to ECDSA key)")
    private Boolean dsaPlain = Boolean.FALSE;

    @Option(name = "--gm",
        description = "whether to use the chinese GM algorithm for the POPO computation\n"
            + "(only applied to EC key with GM curves)")
    private Boolean gm = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      KeyStore ks = KeyStore.getInstance("PKCS11", XiSecurityConstants.PROVIDER_NAME_XIPKI);
      ks.load(null, null);
      if (verbose.booleanValue()) {
        println("available aliases:");
        Enumeration<?> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
          String alias2 = (String) aliases.nextElement();
          println("    " + alias2);
        }
      }

      String alias = getAlias();
      println("alias: " + alias);
      PrivateKey key = (PrivateKey) ks.getKey(alias, null);
      if (key == null) {
        println("could not find key with alias '" + alias + "'");
        return null;
      }

      Certificate cert = ks.getCertificate(alias);
      if (cert == null) {
        println("could not find certificate to verify signature");
        return null;
      }
      PublicKey pubKey = cert.getPublicKey();

      String sigAlgo = getSignatureAlgo(pubKey);
      println("signature algorithm: " + sigAlgo);
      Signature sig = Signature.getInstance(sigAlgo, XiSecurityConstants.PROVIDER_NAME_XIPKI);
      sig.initSign(key);

      byte[] data = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
      sig.update(data);
      byte[] signature = sig.sign(); // CHECKSTYLE:SKIP
      println("signature created successfully");

      Signature ver = Signature.getInstance(sigAlgo, "BC");
      ver.initVerify(pubKey);
      ver.update(data);
      boolean valid = ver.verify(signature);
      println("signature valid: " + valid);
      return null;
    }

    private String getAlias() {
      if (label != null) {
        return StringUtil.concat(moduleName, "#slotindex-", slotIndex.toString(),
            "#keylabel-", label);
      } else {
        return StringUtil.concat(moduleName, "#slotindex-", slotIndex.toString(),
            "#keyid-", id.toLowerCase());
      }
    }

    private String getSignatureAlgo(PublicKey pubKey) throws NoSuchAlgorithmException {
      SignatureAlgoControl algoControl = new SignatureAlgoControl(rsaMgf1, dsaPlain, gm);
      AlgorithmIdentifier sigAlgId = AlgorithmUtil.getSigAlgId(pubKey,
          HashAlgo.getNonNullInstance(hashAlgo), algoControl);
      return AlgorithmUtil.getSignatureAlgoName(sigAlgId);
    }

  }

  @Command(scope = "xi", name = "refresh-p11", description = "refresh PKCS#11 module")
  @Service
  public static class RefreshP11 extends SecurityAction {

    @Option(name = "--module",  description = "name of the PKCS#11 module.")
    @Completion(SecurityCompleters.P11ModuleNameCompleter.class)
    private String moduleName = P11SecurityAction.DEFAULT_P11MODULE_NAME;

    @Reference
    P11CryptServiceFactory p11CryptServiceFactory;

    @Override
    protected Object execute0() throws Exception {
      P11CryptService p11Service = p11CryptServiceFactory.getP11CryptService(moduleName);
      if (p11Service == null) {
        throw new IllegalCmdParamException("undefined module " + moduleName);
      }
      p11Service.refresh();
      println("refreshed module " + moduleName);
      return null;
    }

  }

  @Command(scope = "xi", name = "rsa-p11", description = "generate RSA keypair in PKCS#11 device")
  @Service
  public static class RsaP11 extends P11KeyGenAction {

    @Option(name = "--key-size", description = "keysize in bit")
    private Integer keysize = 2048;

    @Option(name = "-e", description = "public exponent")
    private String publicExponent = "0x10001";

    @Override
    protected Object execute0() throws Exception {
      if (keysize % 1024 != 0) {
        throw new IllegalCmdParamException("keysize is not multiple of 1024: " + keysize);
      }

      P11Slot slot = getSlot();
      P11IdentityId identityId = slot.generateRSAKeypair(keysize, toBigInt(publicExponent),
          getControl());
      finalize("RSA", identityId);
      return null;
    }

  }

  @Command(scope = "xi", name = "secretkey-p11",
      description = "generate secret key in PKCS#11 device")
  @Service
  public static class SecretkeyP11 extends P11KeyGenAction {

    private static final Logger LOG = LoggerFactory.getLogger(SecretkeyP11.class);

    @Option(name = "--key-type", required = true,
        description = "keytype, current only AES, DES3 and GENERIC are supported")
    @Completion(SecurityCompleters.SecretKeyTypeCompleter.class)
    private String keyType;

    @Option(name = "--key-size", required = true, description = "keysize in bit")
    private Integer keysize;

    @Option(name = "--extern-if-gen-unsupported",
        description = "If set, if the generation mechanism is not supported by the PKCS#11 "
            + "device, create in memory and then import it to the device")
    private Boolean createExternIfGenUnsupported = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      if (keysize % 8 != 0) {
        throw new IllegalCmdParamException("keysize is not multiple of 8: " + keysize);
      }

      long p11KeyType;
      if ("AES".equalsIgnoreCase(keyType)) {
        p11KeyType = PKCS11Constants.CKK_AES;
      } else if ("DES3".equalsIgnoreCase(keyType)) {
        p11KeyType = PKCS11Constants.CKK_DES3;
      } else if ("GENERIC".equalsIgnoreCase(keyType)) {
        p11KeyType = PKCS11Constants.CKK_GENERIC_SECRET;
      } else {
        throw new IllegalCmdParamException("invalid keyType " + keyType);
      }

      P11Slot slot = getSlot();
      P11NewKeyControl control = getControl();

      P11IdentityId identityId = null;
      try {
        identityId = slot.generateSecretKey(p11KeyType, keysize, control);
        finalize(keyType, identityId);
      } catch (P11UnsupportedMechanismException ex) {
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

        P11ObjectIdentifier objId = slot.importSecretKey(p11KeyType, keyValue, control);
        Arrays.fill(keyValue, (byte) 0); // clear the memory
        println("generated in memory and imported " + keyType + " key " + objId);
      }

      return null;
    }

  }

  @Command(scope = "xi", name = "import-secretkey-p11",
      description = "import secret key with given value in PKCS#11 device")
  @Service
  public static class ImportSecretkeyP11 extends P11KeyGenAction {

    @Option(name = "--key-type", required = true,
        description = "keytype, current only AES, DES3 and GENERIC are supported")
    @Completion(SecurityCompleters.SecretKeyTypeCompleter.class)
    private String keyType;

    @Option(name = "--keystore", required = true,
        description = "JCEKS keystore from which the key is imported")
    @Completion(FileCompleter.class)
    private String keyOutFile;

    @Option(name = "--password", description = "password of the keystore file")
    private String password;

    @Override
    protected Object execute0() throws Exception {
      long p11KeyType;
      if ("AES".equalsIgnoreCase(keyType)) {
        p11KeyType = PKCS11Constants.CKK_AES;

      } else if ("DES3".equalsIgnoreCase(keyType)) {
        p11KeyType = PKCS11Constants.CKK_DES3;
      } else if ("GENERIC".equalsIgnoreCase(keyType)) {
        p11KeyType = PKCS11Constants.CKK_GENERIC_SECRET;
      } else {
        throw new IllegalCmdParamException("invalid keyType " + keyType);
      }

      KeyStore ks = KeyStore.getInstance("JCEKS");
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
          keyValue = ((SecretKey) key).getEncoded();
          break;
        }
      }

      if (keyValue == null) {
        throw new IllegalCmdParamException("keystore does not contain secret key");
      }

      P11Slot slot = getSlot();
      P11ObjectIdentifier objId = slot.importSecretKey(p11KeyType, keyValue, getControl());
      println("imported " + keyType + " key " + objId);
      return null;
    }

    protected char[] getPassword() throws IOException {
      char[] pwdInChar = readPasswordIfNotSet(password);
      if (pwdInChar != null) {
        password = new String(pwdInChar);
      }
      return pwdInChar;
    }

  }

  public abstract static class P11SecurityAction extends SecurityAction {

    protected static final String DEFAULT_P11MODULE_NAME =
        P11CryptServiceFactory.DEFAULT_P11MODULE_NAME;

    @Option(name = "--slot", required = true, description = "slot index")
    protected Integer slotIndex;

    @Option(name = "--module", description = "name of the PKCS#11 module")
    @Completion(SecurityCompleters.P11ModuleNameCompleter.class)
    protected String moduleName = DEFAULT_P11MODULE_NAME;

    @Reference (optional = true)
    protected P11CryptServiceFactory p11CryptServiceFactory;

    protected P11Slot getSlot()
        throws XiSecurityException, P11TokenException, IllegalCmdParamException {
      P11Module module = getP11Module(moduleName);
      P11SlotIdentifier slotId = module.getSlotIdForIndex(slotIndex);
      return module.getSlot(slotId);
    }

    protected P11Module getP11Module(String moduleName)
        throws XiSecurityException, P11TokenException, IllegalCmdParamException {
      P11CryptService p11Service = p11CryptServiceFactory.getP11CryptService(moduleName);
      if (p11Service == null) {
        throw new IllegalCmdParamException("undefined module " + moduleName);
      }
      return p11Service.getModule();
    }

    public P11ObjectIdentifier getObjectIdentifier(String hexId, String label)
        throws IllegalCmdParamException, XiSecurityException, P11TokenException {
      P11Slot slot = getSlot();
      P11ObjectIdentifier objIdentifier;
      if (hexId != null && label == null) {
        objIdentifier = slot.getObjectId(Hex.decode(hexId), null);
      } else if (hexId == null && label != null) {
        objIdentifier = slot.getObjectId(null, label);
      } else {
        throw new IllegalCmdParamException(
            "exactly one of keyId or keyLabel should be specified");
      }
      return objIdentifier;
    }

  }

  @Command(scope = "xi", name = "sm2-p11",
      description = "generate SM2 (curve sm2p256v1) keypair in PKCS#11 device")
  @Service
  public static class Sm2P11 extends P11KeyGenAction {

    @Override
    protected Object execute0() throws Exception {
      P11Slot slot = getSlot();
      P11IdentityId identityId = slot.generateSM2Keypair(getControl());
      finalize("SM2", identityId);
      return null;
    }

  }

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

      List<P11SlotIdentifier> slots = module.getSlotIds();
      if (slotIndex == null) {
        output(slots);
        return null;
      }

      P11SlotIdentifier slotId = module.getSlotIdForIndex(slotIndex);
      P11Slot slot = module.getSlot(slotId);
      println("Details of slot");
      slot.showDetails(System.out, verbose);
      System.out.println();
      System.out.flush();
      return null;
    }

    private void output(List<P11SlotIdentifier> slots) {
      // list all slots
      final int n = slots.size();

      if (n == 0 || n == 1) {
        String numText = (n == 0) ? "no" : "1";
        println(numText + " slot is configured");
      } else {
        println(n + " slots are configured");
      }

      for (P11SlotIdentifier slotId : slots) {
        println("\tslot[" + slotId.getIndex() + "]: " + slotId.getId());
      }
    }

  }

}
