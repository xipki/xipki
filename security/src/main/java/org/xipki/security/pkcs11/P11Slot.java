// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.*;
import org.xipki.pkcs11.wrapper.attrs.AttributeTypes;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.spec.PKCS11KeyPairSpec;
import org.xipki.pkcs11.wrapper.spec.PKCS11SecretKeySpec;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.pkcs11.wrapper.type.CkMechanismInfo;
import org.xipki.pkcs11.wrapper.type.CkSlotInfo;
import org.xipki.pkcs11.wrapper.type.CkTokenInfo;
import org.xipki.security.KeySpec;
import org.xipki.security.OIDs;
import org.xipki.security.exception.XiSecurityException;
import org.xipki.security.pkcs11.P11ModuleConf.P11MechanismFilter;
import org.xipki.security.pkix.KeyInfoPair;
import org.xipki.security.util.EcCurveEnum;
import org.xipki.security.util.KeyUtil;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Hex;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.misc.StringUtil;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * PKCS#11 slot.
 *
 * @author Lijun Liao
 */
public class P11Slot implements Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(P11Slot.class);

  public static final AlgorithmIdentifier ALGID_RSA = new AlgorithmIdentifier(
      OIDs.Algo.id_rsaEncryption, DERNull.INSTANCE);

  private final String moduleName;

  private final P11SlotId slotId;

  private final boolean readOnly;

  private final Map<Long, CkMechanismInfo> mechanisms = new HashMap<>();

  private final PKCS11Token token;

  private final CkSlotInfo slotInfo;

  private String libDesc;

  public P11Slot(String moduleName, P11SlotId slotId, PKCS11Token token,
                 P11MechanismFilter mechanismFilter)
      throws TokenException {
    this.moduleName = Args.notBlank(moduleName, "moduleName");
    this.slotId = Args.notNull(slotId, "slotId");
    this.readOnly = token.isReadOnly();

    if (slotId.id() != token.getTokenId()) {
      throw new IllegalArgumentException("slotId != token.getTokenId");
    }

    this.token = Args.notNull(token, "slot");

    libDesc = token.getModule().getInfo().libraryDescription();
    if (libDesc == null) {
      libDesc = "";
    }

    initMechanisms(getSupportedMechanisms(), mechanismFilter);

    CkSlotInfo si = null;
    try {
      si = token.getToken().getSlot().getSlotInfo();
    } catch (TokenException e) {
      LOG.warn("error getting slotInfo", e);
    }
    slotInfo = si;
  }

  private static String getDescription(byte[] keyId, String keyLabel) {
    return StringUtil.concat("id ",
        (keyId == null ? "null" : Hex.encode(keyId)), " and label ",
        keyLabel);
  }

  private void initMechanisms(
      Map<Long, CkMechanismInfo> supportedMechanisms,
      P11MechanismFilter mechanismFilter) {
    mechanisms.clear();

    List<Long> ignoreMechs = new ArrayList<>();
    PKCS11Module pkcs11Module = token.getModule();

    for (Map.Entry<Long, CkMechanismInfo> entry
        : supportedMechanisms.entrySet()) {
      long mech = entry.getKey();
      if (mechanismFilter.isMechanismPermitted(slotId, mech, pkcs11Module)) {
        mechanisms.put(mech, entry.getValue());
      } else {
        ignoreMechs.add(mech);
      }
    }
    Collections.sort(ignoreMechs);

    if (LOG.isInfoEnabled()) {
      StringBuilder sb = new StringBuilder().append("initialized module ")
          .append(moduleName).append(", slot ").append(slotId);

      sb.append("\nsupported mechanisms:\n");
      if (mechanisms.isEmpty()) {
        sb.append("  NONE\n");
      } else {
        printMechanisms(sb, mechanisms);
      }

      sb.append("\nsupported by device but ignored mechanisms:\n");
      if (ignoreMechs.isEmpty()) {
        sb.append("  NONE\n");
      } else {
        for (Long mech : ignoreMechs) {
          sb.append("\n  ").append(mechanismCodeToName(mech));
        }
      }
      LOG.info(sb.toString());
    }
  }

  private void printMechanisms(
      StringBuilder sb, Map<Long, CkMechanismInfo> mechanisms) {
    List<Long> sortedMechs = new ArrayList<>(mechanisms.keySet());
    Collections.sort(sortedMechs);

    for (long mech : sortedMechs) {
      sb.append("  ").append(mechanismCodeToName(mech)).append("(0x")
          .append(Functions.toFullHex(mech)).append(")\n")
          .append(mechanisms.get(mech).toString(null, "  ")).append("\n");
    }
  }

  public Map<Long, CkMechanismInfo> mechanisms() {
    return Collections.unmodifiableMap(mechanisms);
  }

  public void assertMechSupported(long mechanism, long flagBit)
      throws TokenException {
    if (supportsMechanism(mechanism, flagBit)) {
      return;
    }

    throw new TokenException("mechanism " + mechanismCodeToName(mechanism) +
        " for " + codeToName(Category.CKF_MECHANISM, flagBit) +
        " is not supported by PKCS11 slot " + slotId);
  }

  public String moduleName() {
    return moduleName;
  }

  public P11SlotId slotId() {
    return slotId;
  }

  private void assertNoObjects(byte[] id, String label) throws TokenException {
    if (id == null && label == null) {
      return;
    }

    if (objectExistsByIdLabel(id, label)) {
      throw new TokenException("Objects with " + getDescription(id, label) +
          " already exists");
    }
  }

  /**
   * Remove objects.
   *
   * @param id
   *        ID of the objects to be deleted. At least one of id and label
   *        may not be {@code null}.
   * @param label Label of the objects to be deleted
   * @return number of deleted objects.
   * @throws TokenException If PKCS#11 error happens.
   */
  public int destroyObjectsByIdLabel(byte[] id, String label)
      throws TokenException {
    return token.destroyObjectsByIdLabel(id, label);
  }

  /**
   * Generates a secret key in the PKCS#11 token.
   *
   * @param keyBitLength Key size in bit
   * @param spec
   *        Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#11 token.
   * @throws TokenException if PKCS#11 token exception occurs.
   */
  public PKCS11KeyId generateSecretKey(
      Integer keyBitLength, PKCS11SecretKeySpec spec)
      throws TokenException {
    assertWritable("generateSecretKey");
    assertNoObjects(Args.notNull(spec, "spec").id(), spec.label());

    long keyType = spec.keyType();
    if (keyBitLength == null) {
      if (keyType != CKK_VENDOR_SM4) {
        throw new IllegalArgumentException("keyBitLength is required for key " +
            ckkCodeToName(keyType) + " but is not specified");
      }
    } else if (keyBitLength % 8 != 0) {
      throw new IllegalArgumentException(
          "keyBitLength is not multiple of 8: " + keyBitLength);
    }

    boolean hasValueLen = true;
    if (!hasValueLen) {
      keyBitLength = null;
    }

    spec.keyType(keyType);
    if (keyBitLength != null) {
      spec.valueLen(keyBitLength / 8);
    }

    return token.generateKey(spec);
  }

  /**
   * Imports secret key object in the PKCS#11 token. The key itself will not be
   * generated within the PKCS#11 token.
   *
   * @param keyValue Key value. Must not be {@code null}.
   * @param spec
   *        Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#11 token.
   * @throws TokenException if PKCS#11 token exception occurs.
   */
  public PKCS11KeyId importSecretKey(
      byte[] keyValue, PKCS11SecretKeySpec spec)
      throws TokenException {
    assertWritable("createSecretKey");
    assertNoObjects(Args.notNull(spec, "spec").id(), spec.label());
    return token.importSecretKey(keyValue, spec);
  }

  /**
   * Generates a keypair.
   *
   * @param keySpec key specification. Must not be {@code null}.
   * @param spec
   *        Control of the key generation process. Must not be {@code null}.
   * @return the identifier of the key within the PKCS#P11 token.
   * @throws TokenException if PKCS#11 token exception occurs.
   */
  public PKCS11KeyId generateKeyPair(KeySpec keySpec, PKCS11KeyPairSpec spec)
      throws TokenException {
    assertKeyPairGenerationAlgoSupported(keySpec);
    spec.keyPairType(keySpec.type());
    return token.generateKeyPair(spec);
  }

  /**
   * Generates a keypair on-the-fly.
   *
   * @param keySpec key spec
   * @return the ASN.1 keypair.
   * @throws XiSecurityException
   *         if exception occurs.
   */
  public KeyInfoPair generateKeyPairOtf(KeySpec keySpec)
      throws XiSecurityException {
    PKCS11KeyId keypair = null;

    try {
      assertKeyPairGenerationAlgoSupported(keySpec);
      PKCS11KeyPairSpec template = new PKCS11KeyPairSpec()
          .keyPairType(keySpec.type())
          .sensitive(false).extractable(true).token(false);
      keypair = token.generateKeyPair(template);

      if (keySpec.isRSA()) {
        Template attrs = token.getAttrValues(keypair.getHandle(),
            new AttributeTypes().modulus().publicExponent().privateExponent()
                .prime1().prime2().exponent1().exponent2().coefficient());
        PrivateKeyInfo priKeyInfo = new PrivateKeyInfo(ALGID_RSA,
            new org.bouncycastle.asn1.pkcs.RSAPrivateKey(
                attrs.modulus(), attrs.publicExponent(),
                attrs.privateExponent(), attrs.prime1(), attrs.prime2(),
                attrs.exponent1(), attrs.exponent2(), attrs.coefficient()));
        SubjectPublicKeyInfo pubKeyInfo = new SubjectPublicKeyInfo(ALGID_RSA,
            new org.bouncycastle.asn1.pkcs.RSAPublicKey(
                attrs.modulus(), attrs.publicExponent()));
        return new KeyInfoPair(pubKeyInfo, priKeyInfo);
      } else if (keySpec.isWeierstrassEC() || keySpec.isEdwardsEC() ||
          keySpec.isMontgomeryEC()) {
        byte[] ecPoint = token.getAttrValues(keypair.getPublicKeyHandle(),
            new AttributeTypes().ecPoint()).ecPoint();
        byte[] privValue = token.getAttrValues(keypair.getHandle(),
            new AttributeTypes().value()).value();

        AlgorithmIdentifier algId = keySpec.algorithmIdentifier();

        PrivateKeyInfo priKeyInfo;
        if (keySpec.isEdwardsEC() || keySpec.isMontgomeryEC()) {
          priKeyInfo = new PrivateKeyInfo(algId, new DEROctetString(privValue),
              null, ecPoint);
        } else {
          if (ecPoint[0] != 4) {
            throw new TokenException("EcPoint does not start with 0x04");
          }

          Integer orderByteLen = keySpec.ecCurveFieldByteSize();
          assert orderByteLen != null;
          priKeyInfo = new PrivateKeyInfo(algId,
              new org.bouncycastle.asn1.sec.ECPrivateKey(orderByteLen * 8,
                  new BigInteger(1, privValue),
                  new DERBitString(ecPoint), null));
        }

        return new KeyInfoPair(new SubjectPublicKeyInfo(algId, ecPoint),
            priKeyInfo);
      } else {
        throw new XiSecurityException("unsupported keySpec " + keySpec);
      }
    } catch(TokenException | IOException ex){
      throw new XiSecurityException(
          "error generateKeypair for keySpec " + keySpec, ex);
    } finally{
      token.destroyKeyQuietly(keypair);
    }
  }

  private void assertKeyPairGenerationAlgoSupported(KeySpec keySpec)
      throws TokenException {
    if (keySpec.isRSA()) {
      if (!(supportsMechanism(CKM_RSA_X9_31_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR)
          || supportsMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN,
              CKF_GENERATE_KEY_PAIR))) {
        throw new TokenException(buildOrMechanismsUnsupportedMessage(
            CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_RSA_PKCS_KEY_PAIR_GEN));
      }
    } else {
      CkMechanism mech = keySpec.type().getGenerateMechanism();
      assertMechSupported(mech.getMechanism(), CKF_GENERATE_KEY_PAIR);
    }
  }

  private String buildOrMechanismsUnsupportedMessage(long... mechanisms) {
    StringBuilder sb = new StringBuilder("none of mechanisms [");
    for (long mechanism : mechanisms) {
      sb.append(mechanismCodeToName(mechanism)).append(", ");
    }

    return sb.deleteCharAt(sb.length() - 1)
        .append("] is supported by PKCS#11 slot ").append(slotId).toString();
  }

  private void assertWritable(String operationName) throws TokenException {
    if (readOnly) {
      throw new TokenException("Writable operation " + operationName +
          " is not permitted");
    }
  }

  private Map<Long, CkMechanismInfo> getSupportedMechanisms() {
    Set<Long> mechanisms = token.getMechanisms();
    List<Long> newList = new ArrayList<>(mechanisms.size());

    StringBuilder ignoreMechs = new StringBuilder();
    boolean smartcard = libDesc.toLowerCase().contains("smartcard");
    for (long code : mechanisms) {
      if (smartcard) {
        if (code == CKM_ECDSA_SHA1     ||
            code == CKM_ECDSA_SHA224   || code == CKM_ECDSA_SHA256   ||
            code == CKM_ECDSA_SHA384   || code == CKM_ECDSA_SHA512   ||
            code == CKM_ECDSA_SHA3_224 || code == CKM_ECDSA_SHA3_256 ||
            code == CKM_ECDSA_SHA3_384 || code == CKM_ECDSA_SHA3_512) {
          ignoreMechs.append(ckmCodeToName(code)).append(", ");
        } else {
          newList.add(code);
        }
      } else {
        newList.add(code);
      }
    }

    if (ignoreMechs.length() > 0) {
      LOG.info("Ignore mechanisms in smartcard-based HSM: {}",
          ignoreMechs.substring(0, ignoreMechs.length() - 2));
    }

    Map<Long, CkMechanismInfo> ret = new HashMap<>(newList.size() * 5 / 4);
    for (Long mech : newList) {
      CkMechanismInfo info = token.getMechanismInfo(mech);
      if (info == null) {
        LOG.warn("found not MechanismInfo for {}, ignore it",
            ckmCodeToName(mech));
      } else {
        ret.put(mech, info);
      }
    }
    return ret;
  } // method getSupportedMechanisms()

  private String mechanismCodeToName(long code) {
    return token.getModule().codeToName(Category.CKM, code);
  }

  public boolean supportsMechanism(long mechanism, long flagBit) {
    CkMechanismInfo info = mechanisms.get(mechanism);
    if (info == null) {
      long genericCode = token.getModule().vendorToGenericCode(
          Category.CKM, mechanism);

      if (genericCode != mechanism) {
        info = mechanisms.get(genericCode);
      }
    }
    return info != null && info.hasFlagBit(flagBit);
  }

  @Override
  public final void close() {
    token.closeAllSessions();
  }

  public byte[] digestSecretKey(long mech, long handle) throws TokenException {
    assertMechSupported(mech, CKF_DIGEST);
    return token.digestKey(new CkMechanism(mech), handle);
  }

  public byte[] sign(long mechanism, P11Params params, ExtraParams extraParams,
                     long keyHandle, byte[] content) throws TokenException {
    Args.notNull(content, "content");
    assertMechSupported(mechanism, CKF_SIGN);
    CkMechanism mech = (params == null) ? new CkMechanism(mechanism)
                          : params.toMechanism(mechanism, extraParams);
    return token.sign(mech, keyHandle, content);
  }

  public P11Key getKey(PKCS11KeyId keyId) throws TokenException {
    PKCS11Key pkcs11Key = token.getKey(keyId);
    return (pkcs11Key == null) ? null : toIdentity(pkcs11Key);
  }

  public P11Key getKey(byte[] keyId, String keyLabel) throws TokenException {
    PKCS11Key pkcs11Key = token.getKey(keyId, keyLabel);
    return (pkcs11Key == null) ? null : toIdentity(pkcs11Key);
  }

  public PKCS11KeyId getKeyId(byte[] keyId, String keyLabel)
      throws TokenException {
    return token.getKeyId(keyId, keyLabel);
  }

  public PKCS11KeyId getSecretOrPrivateKeyId(byte[] keyId, String keyLabel)
      throws TokenException {
    PKCS11KeyId ret = getKeyId(keyId, keyLabel);
    if (ret == null) {
      return null;
    }

    PKCS11KeyId.KeyIdType type = ret.type();
    if (type == PKCS11KeyId.KeyIdType.PUBLIC_KEY) {
      throw new TokenException("could not find private key or secret key for "
          + getDescription(keyId, keyLabel));
    }

    return ret;
  }

  private P11Key toIdentity(PKCS11Key pkcs11Key) throws TokenException {
    return new P11Key(this, pkcs11Key);
  }

  public PublicKey getPublicKey(long handle) throws TokenException {
    Template attrs = token.getAttrValues(handle,
        new AttributeTypes().keyType().class_());

    Long objClass = attrs.class_();
    Long keyType = attrs.keyType();
    boolean valid = objClass != null && keyType != null;
    if (valid) {
      valid = objClass == CKO_PUBLIC_KEY;
    }

    if (!valid) {
      throw new TokenException("object with " +  handle +
          " is not a public key");
    }

    if (keyType == CKK_RSA) {
      attrs = token.getAttrValues(handle,
          new AttributeTypes().modulus().publicExponent());

      try {
        return KeyUtil.getRSAPublicKey(
            new RSAPublicKeySpec(attrs.modulus(), attrs.publicExponent()));
      } catch (InvalidKeySpecException ex) {
        throw new TokenException(ex.getMessage(), ex);
      }
    } else if (keyType == CKK_EC || keyType == CKK_VENDOR_SM2
        || keyType == CKK_EC_EDWARDS || keyType == CKK_EC_MONTGOMERY) {
      EcCurveEnum curveEnum;
      if (keyType == CKK_VENDOR_SM2) {
        attrs = token.getAttrValues(handle, new AttributeTypes().ecPoint());
        curveEnum = EcCurveEnum.SM2P256V1;
      } else {
        attrs = token.getAttrValues(handle,
            new AttributeTypes().ecPoint().ecParams());

        curveEnum = EcCurveEnum.ofEncodedOid(attrs.ecParams());
      }

      byte[] ecPoint = attrs.ecPoint();
      try {
        return KeyUtil.createECPublicKey(curveEnum, ecPoint);
      } catch (InvalidKeySpecException ex) {
        throw new TokenException(ex.getMessage(), ex);
      }
    } else if (keyType == CKK_ML_DSA) {
      attrs = token.getAttrValues(handle,
          new AttributeTypes().value().parameterSet());

      long variant = Optional.ofNullable(attrs.parameterSet())
          .orElseThrow(()-> new IllegalStateException(
              "found no CKP_PARAMETER_SET"));

      String oid = Optional.ofNullable(getStdMldsaOid(variant))
          .orElseThrow(()-> new TokenException(
              "invalid CKP_PARAMETER_SET " + variant));

      SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(
          new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid)),
          attrs.value());

      try {
        return KeyUtil.getPublicKey(pkInfo);
      } catch (InvalidKeySpecException ex) {
        throw new TokenException(ex.getMessage(), ex);
      }
    } else if (keyType == CKK_ML_KEM) {
      attrs = token.getAttrValues(handle,
          new AttributeTypes().value().parameterSet());
      long variant = Optional.ofNullable(attrs.parameterSet())
          .orElseThrow(() -> new IllegalStateException(
              "found no CKP_PARAMETER_SET"));

      String oid = Optional.ofNullable(getStdMlkemOid(variant))
          .orElseThrow(() -> new IllegalStateException(
              "invalid CKP_PARAMETER_SET " + variant));

      SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(
          new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid)),
          attrs.value());
      try {
        return KeyUtil.getPublicKey(pkInfo);
      } catch (InvalidKeySpecException ex) {
        throw new TokenException(ex.getMessage(), ex);
      }
    } else {
      throw new TokenException("unknown key type " + ckkCodeToName(keyType));
    }
  }

  public boolean objectExistsByIdLabel(byte[] id, String label)
      throws TokenException {
    return token.objectExistsByIdLabel(id, label);
  }

  /**
   * !!!DANGEROUS OPERATION!!! Destroys all objects.
   *
   * @return number of destroyed objects.
   */
  public int destroyAllObjects() {
    try {
      long[] handles = token.findAllObjects(null);
      return token.destroyObjects(handles).length;
    } catch (TokenException e) {
      LogUtil.warn(LOG, e, "error destroyAllObjects()");
      return 0;
    }
  }

  /**
   * Destroys objects.
   *
   * @param handles handles of objects to be destroyed.
   * @return handles of objects which could not been destroyed.
   */
  public long[] destroyObjectsAndReturnFailedHandles(long[] handles) {
    List<Long> handleList = new ArrayList<>(handles.length);
    for (long handle : handles) {
      handleList.add(handle);
    }

    List<Long> destroyedHandles;
    try {
      destroyedHandles = token.destroyObjects(handleList);
    } catch (TokenException e) {
      // only thrown if we could not borrow an active session.
      return handles;
    }

    if (handles.length == destroyedHandles.size()) {
      return new long[0];
    }

    long[] failedHandles = new long[handles.length - destroyedHandles.size()];
    int index = 0;
    for (long handle : handles) {
      if (!destroyedHandles.contains(handle)) {
        failedHandles[index++] = handle;
      }
    }
    return failedHandles;
  }

  Template getAttrValues(long hObject, AttributeTypes types)
      throws TokenException {
    return token.getAttrValues(hObject, types);
  }

  /**
   * Writes the token details to the given {@code stream}.
   * The specified stream remains open after this method returns.
   *
   * @param stream  Output stream. Must not be {@code null}.
   * @param verbose Whether to show the details verbosely.
   * @param hObject If present, only details of this object will be shown.
   * @throws IOException if IO error occurs.
   */
  public void showDetails(OutputStream stream, Long hObject, boolean verbose)
      throws IOException {
    Args.notNull(stream, "stream");

    CkTokenInfo tokenInfo0 = null;
    try {
      tokenInfo0 = token.getToken().getTokenInfo();
    } catch (PKCS11Exception e) {
    }

    String slotInfo  = (this.slotInfo  == null) ? "ERROR"
        : this.slotInfo .toString(null, "  ");

    String tokenInfo = (tokenInfo0 == null) ? "<ERROR>"
        : tokenInfo0.toString(null, "  ");

    stream.write(("\nToken information:\n"  + tokenInfo)
        .getBytes(StandardCharsets.UTF_8));
    stream.write(("\n\nSlot information:\n" + slotInfo)
        .getBytes(StandardCharsets.UTF_8));
    stream.write('\n');

    if (verbose) {
      StringBuilder sb = new StringBuilder();
      sb.append("\nSupported mechanisms:\n");
      printMechanisms(sb, mechanisms);
      stream.write(sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    try {
      if (hObject != null) {
        stream.write(("\nDetails of object with handle " + hObject + "\n")
            .getBytes(StandardCharsets.UTF_8));
        Template attrs = token.getDefaultAttrValues(hObject);
        stream.write(attrs.toString(false, "  ")
            .getBytes(StandardCharsets.UTF_8));
      } else {
        stream.write("\nList of objects:\n".getBytes(StandardCharsets.UTF_8));
        long[] handles = token.findObjects(null, 9999);
        int i = 0;

        for (long handle : handles) {
          i++;

          String text;
          try {
            String objectText = objectToString(handle);
            text = StringUtil.formatAccount(i, 3) + ". " + objectText;
          } catch (Exception ex) {
            text = StringUtil.formatAccount(i, 3) + ". "
                + "Error reading object with handle " + handle;
            LOG.debug(text, ex);
          }

          stream.write(("  " + text + "\n").getBytes(StandardCharsets.UTF_8));
          if ((i) % 10 == 0) {
            stream.flush();
          }
        }
      }
    } catch (TokenException e) {
      String message = "  error: " + e.getMessage();
      stream.write(message.getBytes(StandardCharsets.UTF_8));
      LogUtil.warn(LOG, e, message);
    }

    stream.flush();
  }

  private String objectToString(long handle) throws TokenException {
    Template attrs = token.getAttrValues(handle,
        new AttributeTypes().id().label().class_());
    long objClass = Optional.ofNullable(attrs.class_()).orElseThrow(
        () -> new TokenException("CKA_CLASS is not present."));

    byte[] id = attrs.id();
    String label = attrs.label();

    String keySpec = null;
    if (objClass == CKO_PRIVATE_KEY || objClass == CKO_PUBLIC_KEY
        || objClass == CKO_SECRET_KEY) {
      long keyType = token.getAttrValues(handle,
          new AttributeTypes().keyType()).keyType();

      if (objClass == CKO_SECRET_KEY) {
        int valueLen;
        if (keyType == CKK_VENDOR_SM4) {
          valueLen = 16;
        } else {
          Integer len = token.getAttrValues(handle,
              new AttributeTypes().valueLen()).valueLen();
          valueLen = (len == null) ? 0 : len;
        }

        keySpec = ckkCodeToName(keyType).substring(4) + "/" + (valueLen * 8);
      } else {
        if (keyType == CKK_RSA) {
          BigInteger modulus = token.getAttrValues(handle,
              new AttributeTypes().modulus()).modulus();
          keySpec = "RSA/" + (modulus == null ? "<N/A>" : modulus.bitLength());
        } else if (keyType == CKK_EC || keyType == CKK_EC_EDWARDS ||
            keyType == CKK_EC_MONTGOMERY) {
          byte[] ecParams = token.getAttrValues(handle,
              new AttributeTypes().ecParams()).ecParams();

          String curveName;
          if (ecParams == null) {
            curveName = "<N/A>";
          } else {
            curveName = Functions.getCurveName(ecParams);
            if (curveName == null) {
              curveName = "0x" + Hex.encode(ecParams);
            }
          }

          keySpec = ckkCodeToName(keyType).substring(4) + "/" + curveName;
        } else if (keyType == CKK_VENDOR_SM2) {
          keySpec = "SM2";
        } else if (keyType == CKK_ML_DSA) {
          Long variant = token.getAttrValues(handle,
              new AttributeTypes().parameterSet()).parameterSet();
          keySpec = (variant == null) ? "MLDSA-NOT-PRESENT"
              : PKCS11T.getStdMldsaName(variant);
          if (keySpec == null) {
            keySpec = "MLDSA-UNKNOWN-" + variant;
          }
        } else if (keyType == CKK_ML_KEM) {
          Long variant = token.getAttrValues(handle,
              new AttributeTypes().parameterSet()).parameterSet();
          keySpec = (variant == null) ? "MLKEM-NOT-PRESENT"
              : PKCS11T.getStdMlkemName(variant);
          if (keySpec == null) {
            keySpec = "MLKEM-UNKNOWN-" + variant;
          }
        } else {
          keySpec = ckkCodeToName(keyType).substring(4);
        }
      }
    }

    String objClassText =
          (objClass == CKO_SECRET_KEY)  ? " Secret Key"
        : (objClass == CKO_PUBLIC_KEY)  ? " Public Key"
        : (objClass == CKO_PRIVATE_KEY) ? "Private Key"
        : (objClass == CKO_CERTIFICATE) ? "Certificate"
        : (objClass == CKO_DATA)        ? "       Data"
        : (objClass == CKO_PROFILE)     ? "    Profile"
        : (objClass == CKO_MECHANISM)   ? "  Mechanism"
        : (objClass == CKO_HW_FEATURE)  ? " HW Feature"
        : (objClass == CKO_DOMAIN_PARAMETERS)
                                        ? "DomainParam"
        : (objClass == CKO_OTP_KEY)     ? "    OTP Key"
        : Long.toString(objClass);

    return  "handle=" + handle +
        ", id=" + (id == null ? "<N/A>" : Hex.encode(id)) +
        ", " + objClassText + (keySpec == null ? "" : ": " + keySpec) +
        ", label=" + (label == null ? "<N/A>" : label);
  }

  static String getStdMldsaOid(long parameterSet) {
    if (parameterSet == CKP_ML_DSA_44) {
      return OIDs.Algo.id_ml_dsa_44.getId();
    } else if (parameterSet == CKP_ML_DSA_65) {
      return OIDs.Algo.id_ml_dsa_65.getId();
    } else if (parameterSet == CKP_ML_DSA_87) {
      return OIDs.Algo.id_ml_dsa_87.getId();
    } else {
      return null;
    }
  }

  static String getStdMlkemOid(long parameterSet) {
    if (parameterSet == CKP_ML_KEM_512) {
      return OIDs.Algo.id_ml_kem_512.getId();
    } else if (parameterSet == CKP_ML_KEM_768) {
      return OIDs.Algo.id_ml_kem_768.getId();
    } else if (parameterSet == CKP_ML_KEM_1024) {
      return OIDs.Algo.id_ml_kem_1024.getId();
    } else {
      return null;
    }
  }

}
