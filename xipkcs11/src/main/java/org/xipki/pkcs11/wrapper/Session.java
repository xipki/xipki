// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.attrs.Attribute;
import org.xipki.pkcs11.wrapper.attrs.AttributeTypes;
import org.xipki.pkcs11.wrapper.attrs.ByteArrayAttribute;
import org.xipki.pkcs11.wrapper.attrs.LongArrayAttribute;
import org.xipki.pkcs11.wrapper.attrs.LongAttribute;
import org.xipki.pkcs11.wrapper.attrs.StringAttribute;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.pkcs11.wrapper.type.CkSessionInfo;
import org.xipki.pkcs11.wrapper.vendor.SpecialBehaviour;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.asn1.Asn1AlgorithmIdentifier;
import org.xipki.util.codec.asn1.Asn1Const;
import org.xipki.util.codec.asn1.Asn1DSAParams;
import org.xipki.util.codec.asn1.Asn1ECPrivateKey;
import org.xipki.util.codec.asn1.Asn1OneAsymmetricKey;
import org.xipki.util.codec.asn1.Asn1RSAPrivateKey;
import org.xipki.util.codec.asn1.Asn1RSAPublicKey;
import org.xipki.util.codec.asn1.Asn1SubjectPublicKey;
import org.xipki.util.codec.asn1.Asn1Util;

import java.math.BigInteger;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import static org.xipki.pkcs11.wrapper.PKCS11T.*;

/**
 * Session objects are used to perform cryptographic operations on a token. The
 * application gets a Session object by calling openSession on a certain Token
 * object. Having the session object, the application may login the user, if
 * required.
 * If the application does not need the session any longer, it should close the
 * session.
 *
 * <pre>
 * <code>
 *   session.closeSession();
 * </code>
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Session {

  private static final Logger LOG = LoggerFactory.getLogger(Session.class);

  private static final byte[] OID_curve25519 =
      Asn1Util.encodeOid("1.3.101.110");

  private static final byte[] OID_curve448 =
      Asn1Util.encodeOid("1.3.101.111");

  private static final byte[] OID_edwards25519 =
      Asn1Util.encodeOid("1.3.101.112");

  private static final byte[] OID_edwards448 =
      Asn1Util.encodeOid("1.3.101.113");

  private static final byte[] NAME_curve25519 =
      Functions.decodeHex("130a63757276653235353139");

  private static final byte[] NAME_curve448 =
      Functions.decodeHex("13086375727665343438");

  private static final byte[] NAME_edwards25519 =
      Functions.decodeHex("130c656477617264733235353139");

  private static final byte[] NAME_edwards448 =
      Functions.decodeHex("130a65647761726473343438");

  private static final int SIGN_TYPE_ECDSA = 1;

  private static final int SIGN_TYPE_SM2 = 2;

  /**
   * A reference to the underlying PKCS#11 module to perform the operations.
   */
  private final PKCS11Module module;

  private final SessionPkcs11 pkcs11;

  /**
   * The token to perform the operations on.
   */
  protected final Token token;

  /**
   * True, if this is an R/W session.
   */
  private Boolean rwSession = null;

  private int signatureType;

  private long signOrVerifyKeyHandle;

  private ExtraParams signVerifyExtraParams;

  /**
   * Constructor taking the token and the session handle.
   *
   * @param token
   *        The token this session operates with.
   * @param sessionHandle
   *        The session handle to perform the operations with.
   */
  protected Session(Token token, long sessionHandle, long openSessionFlags) {
    this.token = Args.notNull(token, "token");
    this.module = token.getSlot().getModule();
    this.pkcs11 = new SessionPkcs11(module.getPKCS11(),
        token, token.getLoginSync(), sessionHandle, openSessionFlags);
  }

  public boolean isRecoverable() {
    return pkcs11.isRecoverable();
  }

  public void setAuth(SessionAuth auth) {
    pkcs11.setAuth(auth);
  }

  /**
   * Closes this session.
   *
   * @throws PKCS11Exception If closing the session failed.
   */
  public void closeSession() throws PKCS11Exception {
    pkcs11.C_CloseSession();
  }

  /**
   * Get the handle of this session.
   *
   * @return The handle of this session.
   */
  public long getSessionHandle() {
    return pkcs11.hSession();
  }

  /**
   * Get information about this session.
   *
   * @return An object providing information about this session.
   * @throws PKCS11Exception
   *         If getting the information failed.
   */
  public CkSessionInfo getSessionInfo() throws PKCS11Exception {
    return pkcs11.C_GetSessionInfo();
  }

  /**
   * Get the Module which this Session object operates with.
   *
   * @return The module of this session.
   */
  public PKCS11Module getModule() {
    return module;
  }

  /**
   * Get the token that created this Session object.
   *
   * @return The token of this session.
   */
  public Token getToken() {
    return token;
  }

  public void login() throws PKCS11Exception {
    pkcs11.login();
  }

  public boolean isLoggedIn() throws PKCS11Exception {
    long state = getSessionInfo().getState();
    return state == CKS_RO_USER_FUNCTIONS || state == CKS_RW_USER_FUNCTIONS
        || state == CKS_RW_SO_FUNCTIONS;
  }

    /**
     * Logs in the user or the security officer to the session. Notice that all
     * sessions of a token have the same login state; i.e. if you login the user
     * to one session all other open sessions of this token get user rights.
     *
     * @param userType
     *        CKU_SO for the security officer or CKU_USER to login the user.
     * @param pin
     *        The PIN. The security officer-PIN or the user-PIN depending on the
     *        userType parameter.
     * @throws PKCS11Exception
     *         If login fails.
     */
  public void login(long userType, byte[] pin) throws PKCS11Exception {
    pkcs11.C_Login(userType, pin);
  }

  /**
   * Logs out this session.
   *
   * @throws PKCS11Exception
   *         If logging out the session fails.
   */
  public void logout() throws PKCS11Exception {
    pkcs11.C_Logout();
  }

  /**
   * Create a new object on the token (or in the session). The application must
   * provide a template that holds enough information to create a certain
   * object. For instance, if the application wants to create a new DES key
   * object it creates a new instance of the AttributesTemplate class to serve
   * as a template. The application must set all attributes of this new object
   * which are required for the creation of such an object on the token. Then
   * it passes this DESSecretKey object to this method to create the object on
   * the token.
   * <p/>
   *
   * Example: <code>
   * AttributesTemplate desKeyTemplate =
   *     AttributesTemplate.newSecretKey(CKK_DES3);
   * // the key type is set by the DESSecretKey's constructor, so you need
   * // not do it
   * desKeyTemplate.value(myDesKeyValueAs8BytesLongByteArray)
   *     .token(true)
   *     .private(true);
   *     .encrypt(true);
   *     .decrypt(true);
   *
   * ...
   *
   * long theCreatedDESKeyObjectHandle =
   *     userSession.createObject(desKeyTemplate);
   * </code>
   *
   * Refer to the PKCS#11 standard to find out what attributes must be set for
   * certain types of objects to create them on the token.
   *
   * @param template
   *        The template object that holds all values that the new object on
   *        the token should contain.
   * @return A new PKCS#11 Object that serves holds all the (readable)
   *         attributes of the object on the token. In contrast to the
   *         templateObject, this object might have certain attributes set to
   *         token-dependent default-values.
   * @throws PKCS11Exception
   *         If the creation of the new object fails. If it fails, the no new
   *         object was created on the token.
   */
  public long importObject(Template template) throws PKCS11Exception {
    long hObject = pkcs11.C_CreateObject(toOutCKAttrs(template));
    traceObject("created object", hObject);
    return hObject;
  }

  public PKCS11KeyPair importKeyPair(
      PrivateKeyChoice privateKey, PublicKeyChoice publicKey,
      KeyPairTemplate template)
      throws InvalidKeySpecException, TokenException {
    Args.notNull(privateKey, "privateKey");

    Asn1OneAsymmetricKey asn1Sk =
        Asn1OneAsymmetricKey.getInstance(privateKey.getEncoded());
    String oid = asn1Sk.getPrivateKeyAlgorithm().getOid();

    byte[] publicKeyData = asn1Sk.getPublicKey();
    Asn1RSAPrivateKey rsaSk = null;

    // pre-check the match or private key and public key
    if (publicKey != null) {
      Asn1SubjectPublicKey asn1Pk =
          Asn1SubjectPublicKey.getInstance(publicKey.getEncoded());
      if (!asn1Sk.getPrivateKeyAlgorithm().equals(asn1Pk.getAlgId())) {
        throw new InvalidKeySpecException("privateKey and publicKey " +
            "do not have the same AlgorithmIdentifier");
      }

      if (publicKeyData != null) {
        if (!Arrays.equals(publicKeyData, asn1Pk.getPublicKeyData())) {
          throw new InvalidKeySpecException("privateKey and publicKey " +
              "do not have the same publicKey data");
        }
      } else if (Asn1Const.id_rsaPublicKey.equals(oid)) {
        rsaSk = Asn1RSAPrivateKey.getInstance(asn1Sk.getPrivateKey());
        Asn1RSAPublicKey rsaPk = Asn1RSAPublicKey.getInstance(
            asn1Pk.getPublicKeyData());
        if (!(Arrays.equals(rsaSk.getModulus(), rsaPk.getModulus())
              && Arrays.equals(rsaSk.getPublicExponent(),
                    rsaPk.getPublicExponent()))) {
          throw new InvalidKeySpecException("RSA privateKey and publicKey " +
              "do not have the same publicKey data");
        }

        publicKeyData = asn1Pk.getPublicKeyData();
      }
    }

    if (publicKeyData == null) {
      if (Asn1Const.id_rsaPublicKey.equals(oid)) {
        if (rsaSk == null) {
          rsaSk = Asn1RSAPrivateKey.getInstance(asn1Sk.getPrivateKey());
        }

        publicKeyData = Asn1Util.toTLV(Asn1Const.TAG_SEQUENCE,
            Asn1Util.toAsn1Int(rsaSk.getModulus()),
            Asn1Util.toAsn1Int(rsaSk.getPublicExponent()));
      }
    }

    if (publicKeyData == null) {
      throw new InvalidKeySpecException("could not extract public key data");
    }

    Template pubTemplate = template.publicKey();

    long hPublicKey = importPublicKey(asn1Sk.getPrivateKeyAlgorithm(),
        publicKeyData, pubTemplate);

    boolean succ = false;
    try {
      long hPrivateKey = importPrivateKey(asn1Sk.getPrivateKeyAlgorithm(),
          asn1Sk.getPrivateKey(), publicKeyData, template.privateKey());
      succ = true;
      return new PKCS11KeyPair(hPublicKey, hPrivateKey);
    } finally {
      if (!succ) {
        destroyObject(hPublicKey);
      }
    }
  }

  public long importPublicKey(
      PublicKeyChoice publicKey, Template template)
      throws InvalidKeySpecException, PKCS11Exception {
    byte[] encoded = publicKey.getEncoded();
    Asn1SubjectPublicKey asn1Pk = Asn1SubjectPublicKey.getInstance(encoded);
    return importPublicKey(asn1Pk.getAlgId(), asn1Pk.getPublicKeyData(),
        template);
  }

  private long importPublicKey(
      Asn1AlgorithmIdentifier algId, byte[] publicKeyData,
      Template template)
      throws InvalidKeySpecException, PKCS11Exception {
    String oid = algId.getOid();
    byte[] params = algId.getParams();

    long dfltKeyType;
    switch (oid) {
      case Asn1Const.id_rsaPublicKey: {
        dfltKeyType = CKK_RSA;
        Asn1RSAPublicKey tKey = Asn1RSAPublicKey.getInstance(publicKeyData);
        template.modulus(toUBigInt(tKey.getModulus()))
            .publicExponent(toUBigInt(tKey.getPublicExponent()));
        break;
      }
      case Asn1Const.id_ecPublicKey: {
        dfltKeyType = CKK_EC;
        String curveOid = Asn1Util.decodeOid(params);
        if (Asn1Const.id_sm2p256v1.equals(curveOid)) {
          dfltKeyType = CKK_VENDOR_SM2;
        }

        template.ecParams(params)
            .ecPoint(publicKeyData);
        break;
      }
      case Asn1Const.id_dsaPublicKey: {
        dfltKeyType = CKK_DSA;
        Asn1DSAParams dsaParams = Asn1DSAParams.getInstance(params);
        byte[] value;
        try {
          value = Asn1Util.readBigInt(publicKeyData);
        } catch (CodecException e) {
          throw new InvalidKeySpecException(e);
        }

        template.prime(toUBigInt(dsaParams.getP()))
            .subprime(toUBigInt(dsaParams.getQ()))
            .base(toUBigInt(dsaParams.getG()))
            .value(asUnsigned(value));
        break;
      }
      case Asn1Const.id_x25519:
      case Asn1Const.id_x448:
      case Asn1Const.id_ed25519:
      case Asn1Const.id_ed448: {
        boolean xdh = Asn1Const.id_x25519.equals(oid)
            || Asn1Const.id_x448.equals(oid);
        dfltKeyType = xdh ? CKK_EC_MONTGOMERY : CKK_EC_EDWARDS;

        template.ecParams(Asn1Util.encodeOid(oid))
            .ecPoint(publicKeyData);
        break;
      }
      case Asn1Const.id_mldsa44:
      case Asn1Const.id_mldsa65:
      case Asn1Const.id_mldsa87: {
        dfltKeyType = CKK_ML_DSA;
        long variant = Asn1Const.id_mldsa44.equals(oid) ? CKP_ML_DSA_44
            : Asn1Const.id_mldsa65.equals(oid) ? CKP_ML_DSA_65
            : CKP_ML_DSA_87;
        template.parameterSet(variant)
            .value(publicKeyData);
        break;
      }
      case Asn1Const.id_mlkem512:
      case Asn1Const.id_mlkem768:
      case Asn1Const.id_mlkem1024: {
        dfltKeyType = CKK_ML_KEM;
        long variant = Asn1Const.id_mlkem512.equals(oid) ? CKP_ML_KEM_512
            : Asn1Const.id_mlkem768.equals(oid) ? CKP_ML_KEM_768
            : CKP_ML_KEM_1024;
        template.parameterSet(variant)
            .value(publicKeyData);
        break;
      }
      default:
        throw new InvalidKeySpecException("unsupported public key " + oid);
    }

    if (template.keyType() == null) {
      template.keyType(dfltKeyType);
    }

    return importObject(template);
  }

  public long importPrivateKey(
      PrivateKeyChoice privateKey, PublicKeyChoice publicKey,
      Template template)
      throws InvalidKeySpecException, PKCS11Exception {
    Asn1OneAsymmetricKey asn1Sk =
        Asn1OneAsymmetricKey.getInstance(privateKey.getEncoded());

    byte[] publicKeyData = asn1Sk.getPublicKey();
    if (publicKeyData == null && publicKey != null) {
      publicKeyData = Asn1SubjectPublicKey.getInstance(
          publicKey.getEncoded()).getPublicKeyData();
    }

    return importPrivateKey(asn1Sk.getPrivateKeyAlgorithm(),
        asn1Sk.getPrivateKey(), publicKeyData, template);
  }

  private long importPrivateKey(
      Asn1AlgorithmIdentifier algId, byte[] privateKeyData,
      byte[] publicKeyData, Template template)
      throws InvalidKeySpecException, PKCS11Exception {
    String oid = algId.getOid();
    byte[] params = algId.getParams();

    try {
      long dfltKeyType;
      switch (oid) {
        case Asn1Const.id_rsaPublicKey: {
          dfltKeyType = CKK_RSA;
          Asn1RSAPrivateKey tKey =
              Asn1RSAPrivateKey.getInstance(privateKeyData);
          template.modulus(toUBigInt(tKey.getModulus()))
              .publicExponent(toUBigInt(tKey.getPublicExponent()))
              .privateExponent(toUBigInt(tKey.getPrivateExponent()))
              .prime1(toUBigInt(tKey.getPrime1()))
              .prime2(toUBigInt(tKey.getPrime2()))
              .exponent1(toUBigInt(tKey.getExponent1()))
              .exponent2(toUBigInt(tKey.getExponent2()))
              .coefficient(toUBigInt(tKey.getCoefficient()));
          break;
        }
        case Asn1Const.id_ecPublicKey: {
          dfltKeyType = CKK_EC;
          String curveOid = Asn1Util.decodeOid(params);
          Asn1ECPrivateKey ecPrivateKey =
              Asn1ECPrivateKey.getInstance(privateKeyData);

          if (Asn1Const.id_sm2p256v1.equals(curveOid)) {
            dfltKeyType = CKK_VENDOR_SM2;
          }

          if (privateKeyWithEcPoint(dfltKeyType)) {
            if (publicKeyData != null) {
              template.ecPoint(publicKeyData);
            } else if (ecPrivateKey.getPublicKey() != null) {
              template.ecPoint(ecPrivateKey.getPublicKey());
            }
          }

          template.ecParams(params)
              .value(ecPrivateKey.getPrivateKey());
          break;
        }
        case Asn1Const.id_dsaPublicKey: {
          dfltKeyType = CKK_DSA;
          Asn1DSAParams dsaParams = Asn1DSAParams.getInstance(params);
          byte[] value = Asn1Util.readBigInt(privateKeyData);

          template.prime(toUBigInt(dsaParams.getP()))
              .subprime(toUBigInt(dsaParams.getQ()))
              .base(toUBigInt(dsaParams.getG()))
              .value(asUnsigned(value));
          break;
        }
        case Asn1Const.id_x25519:
        case Asn1Const.id_x448:
        case Asn1Const.id_ed25519:
        case Asn1Const.id_ed448: {
          boolean xdh = Asn1Const.id_x25519.equals(oid)
              || Asn1Const.id_x448.equals(oid);
          dfltKeyType = xdh ? CKK_EC_MONTGOMERY : CKK_EC_EDWARDS;

          template.ecParams(Asn1Util.encodeOid(oid))
              .value(Asn1Util.readOctetsFromASN1OctetString(privateKeyData));
          break;
        }
        case Asn1Const.id_mldsa44:
        case Asn1Const.id_mldsa65:
        case Asn1Const.id_mldsa87: {
          dfltKeyType = CKK_ML_DSA;
          long variant = Asn1Const.id_mldsa44.equals(oid) ? CKP_ML_DSA_44
              : Asn1Const.id_mldsa65.equals(oid) ? CKP_ML_DSA_65
              : CKP_ML_DSA_87;
          template.parameterSet(variant)
              .value(Asn1Util.readOctetsFromASN1OctetString(privateKeyData));
          break;
        }
        case Asn1Const.id_mlkem512:
        case Asn1Const.id_mlkem768:
        case Asn1Const.id_mlkem1024: {
          dfltKeyType = CKK_ML_KEM;
          long variant = Asn1Const.id_mlkem512.equals(oid) ? CKP_ML_KEM_512
              : Asn1Const.id_mlkem768.equals(oid) ? CKP_ML_KEM_768
              : CKP_ML_KEM_1024;
          template.parameterSet(variant)
              .value(Asn1Util.readOctetsFromASN1OctetString(privateKeyData));
          break;
        }
        default:
          throw new InvalidKeySpecException("unsupported public key " + oid);
      }

      if (template.keyType() == null) {
        template.keyType(dfltKeyType);
      }
    } catch (CodecException e) {
      throw new InvalidKeySpecException("invalid private key");
    }

    return importObject(template);
  }

  private static BigInteger toUBigInt(byte[] bytes) {
    return new BigInteger(1, bytes);
  }

  private static byte[] asUnsigned(byte[] bytes) {
    if (bytes.length <= 1) {
      return bytes;
    } else {
      return bytes[0] != 0 ? bytes
          : Arrays.copyOfRange(bytes, 1, bytes.length);
    }
  }

  private boolean privateKeyWithEcPoint(Long keyType) {
    if (keyType == null) {
      return false;
    }

    if (CKK_VENDOR_SM2 == keyType) {
      return module.hasSpecialBehaviour(
          SpecialBehaviour.SM2_PRIVATEKEY_ECPOINT);
    } else if (CKK_EC == keyType) {
      return module.hasSpecialBehaviour(
          SpecialBehaviour.EC_PRIVATEKEY_ECPOINT);
    } else {
      return false;
    }
  }

  /**
   * Copy an existing object. The source object and a template object are
   * given. Any value set in the template object will override the
   * corresponding value from the source object, when the new object is created.
   * See the PKCS#11 standard for details.
   *
   * @param sourceObjectHandle
   *        The source object of the copy operation.
   * @param template
   *        A template object whose attribute values are used for the new
   *        object; i.e. they have higher priority than the attribute values
   *        from the source object. May be null; in that case the new object
   *        is just a one-to-one copy of the sourceObject.
   * @return The new object that is created by copying the source object and
   *         setting attributes to the values given by the template.
   * @throws PKCS11Exception
   *         If copying the object fails for some reason.
   */
  public long copyObject(long sourceObjectHandle, Template template)
      throws PKCS11Exception {
    long hObject = pkcs11.C_CopyObject(sourceObjectHandle,
        toOutCKAttrs(template));
    traceObject("copied object", hObject);
    return hObject;
  }

  /**
   * Gets all present attributes of the given template object and writes them
   * to the object to update on the token (or in the session). Both parameters
   * may refer to the same Java object.
   * <p/>
   *
   * This is possible, because this method only needs the object handle of the
   * objectToUpdate, and gets the attributes to set from the template. This
   * means, an application can get the object using createObject of findObject,
   * then modify attributes of this Java object and then call this method
   * passing this object as both parameters. This will update the object on the
   * token to the values as modified in the Java object.
   *
   * @param objectToUpdateHandle
   *        The attributes of this object get updated.
   * @param template
   *        Gets all present attributes of this template object and sets this
   *        attributes at the objectToUpdate.
   * @throws PKCS11Exception
   *         If updating the attributes fails. All or no attributes are updated.
   */
  public void setAttributeValues(long objectToUpdateHandle,
                                 Template template)
      throws PKCS11Exception {
    pkcs11.C_SetAttributeValue(objectToUpdateHandle, toOutCKAttrs(template));
    traceObject("object (after settingAttributeValues)",
        objectToUpdateHandle);
  }

  /**
   * Destroy a certain object on the token (or in the session). Give the object
   * that you want to destroy. This method uses only the internal object handle
   * of the given object to identify the object.
   *
   * @param hObject
   *        The object handle that should be destroyed.
   * @throws PKCS11Exception
   *        If the object could not be destroyed.
   */
  public void destroyObject(long hObject) throws PKCS11Exception {
    pkcs11.C_DestroyObject(hObject);
  }

  /**
   * Initializes a find operations that provides means to find objects by
   * passing a template object. This method get all set attributes of the
   * template object and searches for all objects on the token that match with
   * these attributes.
   *
   * @param template
   *        The object that serves as a template for searching. If this object
   *        is null, the find operation will find all objects that this session
   *        can see. Notice, that only a user session will see private objects.
   * @throws PKCS11Exception
   *         If initializing the find operation fails.
   */
  public void findObjectsInit(Template template) throws PKCS11Exception {
    pkcs11.C_FindObjectsInit(toOutCKAttrs(template, false));
  }

  /**
   * Finds objects that match the template object passed to findObjectsInit.
   * The application must call findObjectsInit before calling this method. With
   * maxObjectCount the application can specify how many objects to return at
   * once; i.e. the application can get all found objects by subsequent calls
   * to this method like maxObjectCount(1) until it receives an empty array
   * (this method never returns null!).
   *
   * @param maxObjectCount
   *        Specifies how many objects to return with this call.
   * @return An array of found objects. The maximum size of this array is
   *         maxObjectCount, the minimum length is 0. Never returns null.
   * @throws PKCS11Exception
   *         A plain PKCS11Exception if something during PKCS11 FindObject went
   *         wrong, a PKCS11Exception with a nested PKCS11Exception if the
   *         Exception is raised during object parsing.
   */
  public long[] findObjects(int maxObjectCount) throws PKCS11Exception {
    final int countPerCall = 1000;
    if (maxObjectCount <= countPerCall) {
      return findObjects0(maxObjectCount);
    } else {
      List<Long> list = new LinkedList<>();
      for (int i = 0; i < maxObjectCount; i += countPerCall) {
        int numObjects = Math.min(countPerCall, maxObjectCount - i);
        long[] handles = findObjects0(numObjects);
        for (long handle : handles) {
          list.add(handle);
        }
        if (handles.length < numObjects) {
          break;
        }
      }

      long[] ret = new long[list.size()];
      int idx = 0;
      for (Long handle : list) {
        ret[idx++] = handle;
      }
      return ret;
    }
  }

  private long[] findObjects0(int maxObjectCount) throws PKCS11Exception {
    return pkcs11.C_FindObjects(maxObjectCount);
  }

  /**
   * Finalizes a find operation. The application must call this method to
   * finalize a find operation before attempting to start any other operation.
   *
   * @throws PKCS11Exception
   *         If finalizing the current find operation was not possible.
   */
  public void findObjectsFinal() throws PKCS11Exception {
    pkcs11.C_FindObjectsFinal();
  }

  public long[] findAllObjectsSingle(Template template)
      throws PKCS11Exception {
    return findObjectsSingle(template, Integer.MAX_VALUE);
  }

  public long[] findObjectsSingle(Template template, int maxObjectCount)
      throws PKCS11Exception {
    findObjectsInit(template);
    try {
      return findObjects(maxObjectCount);
    } finally {
      findObjectsFinal();
    }
  }

  /**
   * Initializes a new digesting operation. The application must call this
   * method before calling any other digest* operation. Before initializing a
   * new operation, any currently pending operation must be finalized using the
   * appropriate *Final method (e.g. digestFinal()). There are exceptions for
   * dual-function operations. This method requires the mechanism to use for
   * digesting for this operation. For the mechanism the application may use a
   * constant defined in the Mechanism class.
   *
   * @param mechanism
   *        The mechanism to use; e.g. Mechanism.SHA_1.
   * @throws PKCS11Exception
   *         If initializing this operation failed.
   */
  public void digestInit(CkMechanism mechanism) throws PKCS11Exception {
    pkcs11.C_DigestInit(toOutMechanism(mechanism));
  }

  /**
   * Digests the given data with the mechanism given to the digestInit method.
   * This method finalizes the current digesting operation; i.e. the
   * application need (and should) not call digestFinal() after this call. For
   * digesting multiple pieces of data use digestUpdate and digestFinal.
   *
   * @param data
   *        the to-be-digested data
   * @return the message digest. Never returns {@code null}.
   * @throws PKCS11Exception
   *         If digesting the data failed.
   */
  public byte[] digest(byte[] data) throws PKCS11Exception {
    return pkcs11.C_Digest(data, 64);
  }

  public byte[] digestSingle(CkMechanism mechanism, byte[] data)
      throws PKCS11Exception {
    pkcs11.C_DigestInit(mechanism);
    return pkcs11.C_Digest(data, 64);
  }

  /**
   * This method can be used to digest multiple pieces of data; e.g.
   * buffer-size pieces when reading the data from a stream. Digests the given
   * data with the mechanism given to the digestInit method. The application
   * must call digestFinal to get the final result of the digesting after
   * feeding in all data using this method.
   *
   * @param dataPart
   *        Piece of the to-be-digested data
   * @throws PKCS11Exception
   *         If digesting the data failed.
   */
  public void digestUpdate(byte[] dataPart) throws PKCS11Exception {
    pkcs11.C_DigestUpdate(dataPart);
  }

  /**
   * This method is similar to digestUpdate and can be combined with it during
   * one digesting operation. This method digests the value of the given secret
   * key.
   *
   * @param hKey
   *        The key to digest the value of.
   * @throws PKCS11Exception
   *         If digesting the key failed.
   */
  public void digestKey(long hKey) throws PKCS11Exception {
    pkcs11.C_DigestKey(hKey);
  }

  /**
   * This method finalizes a digesting operation and returns the final result.
   * Use this method, if you fed in the data using digestUpdate and/or
   * digestKey. If you used the digest(byte[]) method, you need not (and shall
   * not) call this method, because digest(byte[]) finalizes the digesting
   * itself.
   *
   * @return the message digest. Never returns {@code null}.
   * @throws PKCS11Exception
   *         If calculating the final message digest failed.
   */
  public byte[] digestFinal() throws PKCS11Exception {
    return pkcs11.C_DigestFinal(64);
  }

  /**
   * This method finalizes a digesting operation and returns the final result.
   * Use this method, if you fed in the data using digestUpdate and/or
   * digestKey. If you used the digest(byte[]) method, you need not (and shall
   * not) call this method, because digest(byte[]) finalizes the digesting
   * itself.
   *
   * @param out
   *        buffer for the message digest
   * @param outOfs
   *        buffer offset for the message digest
   * @param outLen
   *        buffer size for the message digest
   * @return the length of message digest
   * @throws PKCS11Exception
   *         If calculating the final message digest failed.
   */
  public int digestFinal(byte[] out, int outOfs, int outLen)
      throws PKCS11Exception {
    byte[] digest = pkcs11.C_DigestFinal(outLen);
    if (digest.length > outLen) {
      throw new PKCS11Exception(CKR_BUFFER_TOO_SMALL);
    }
    System.arraycopy(digest, 0, out, outOfs, digest.length);
    return digest.length;
  }

  /**
   * Initializes a new signing operation. Use it for signatures and MACs. The
   * application must call this method before calling any other sign*
   * operation. Before initializing a new operation, any currently pending
   * operation must be finalized using the appropriate *Final method (e.g.
   * digestFinal()). There are exceptions for dual-function operations. This
   * method requires the mechanism to use for signing and the key for this
   * operation. The key must have set its sign flag. For the mechanism the
   * application may use a constant defined in the Mechanism class.
   * <p/>
   *
   * Notice that the key and the mechanism must be compatible; i.e. you cannot
   * use a DES key with the RSA mechanism.
   *
   * @param mechanism
   *        The mechanism to use; e.g. Mechanism.RSA_PKCS.
   * @param hKey
   *        The signing key to use.
   * @throws PKCS11Exception
   *         If initializing this operation failed.
   */
  public void signInit(CkMechanism mechanism, long hKey)
      throws PKCS11Exception {
    initSignVerify(mechanism, hKey);
    pkcs11.C_SignInit(toOutMechanism(mechanism), hKey);
  }

  private void initSignVerify(CkMechanism mechanism, long hKey) {
    this.signOrVerifyKeyHandle = hKey;

    long code = mechanism.getMechanism();
    if (code == CKM_ECDSA || code == CKM_ECDSA_SHA1 || code == CKM_ECDSA_SHA224
        || code == CKM_ECDSA_SHA256 || code == CKM_ECDSA_SHA384
        || code == CKM_ECDSA_SHA512 || code == CKM_ECDSA_SHA3_224
        || code == CKM_ECDSA_SHA3_256 || code == CKM_ECDSA_SHA3_384
        || code == CKM_ECDSA_SHA3_512) {
      signatureType = SIGN_TYPE_ECDSA;
    } else if (code == CKM_VENDOR_SM2 || code == CKM_VENDOR_SM2_SM3) {
      signatureType = SIGN_TYPE_SM2;
    } else {
      signatureType = 0;
    }

    signVerifyExtraParams = mechanism.getExtraParams();
  }

  /**
   * Signs the given data with the key and mechanism given to the signInit
   * method. This method finalizes the current signing operation; i.e. the
   * application need (and should) not call signFinal() after this call. For
   * signing multiple pieces of data use signUpdate and signFinal.
   *
   * @param data
   *        The data to sign.
   * @return The signed data. Never returns {@code null}.
   * @throws PKCS11Exception
   *         If signing the data failed.
   */
  public byte[] sign(byte[] data, int maxSize)
      throws PKCS11Exception {
    return fixSignOutput(pkcs11.C_Sign(data, maxSize));
  }

  public byte[] signSingle(CkMechanism mechanism, long hKey, byte[] data,
                           int maxSize)
      throws PKCS11Exception {
    initSignVerify(mechanism, hKey);
    CkMechanism vendorMech = toOutMechanism(mechanism);
    pkcs11.C_SignInit(vendorMech, hKey);
    byte[] sig = pkcs11.C_Sign(data, maxSize);
    return fixSignOutput(sig);
  }

  /**
   * This method can be used to sign multiple pieces of data; e.g. buffer-size
   * pieces when reading the data from a stream. Signs the given data with the
   * mechanism given to the signInit method. The application must call
   * signFinal to get the final result of the signing after feeding in all data
   * using this method.
   *
   * @param dataPart
   *        Piece of the to-be-signed data
   * @throws PKCS11Exception
   *         If signing the data failed.
   */
  public void signUpdate(byte[] dataPart) throws PKCS11Exception {
    pkcs11.C_SignUpdate(dataPart);
  }

  /**
   * This method can be used to sign multiple pieces of data; e.g. buffer-size
   * pieces when reading the data from a stream. Signs the given data with the
   * mechanism given to the signInit method. The application must call
   * signFinal to get the final result of the signing after feeding in all
   * data using this method.
   *
   * @param in
   *        buffer containing the to-be-signed data
   * @param inOfs
   *        buffer offset of the to-be-signed data
   * @param inLen
   *        length of the to-be-signed data
   * @throws PKCS11Exception
   *         If signing the data failed.
   */
  public void signUpdate(byte[] in, int inOfs, int inLen)
      throws PKCS11Exception {
    byte[] toHsmIn = (inOfs == 0 && inLen == in.length) ? in
        : Arrays.copyOfRange(in, inOfs, inOfs + inLen);
    pkcs11.C_SignUpdate(toHsmIn);
  }

  /**
   * This method finalizes a signing operation and returns the final result.
   * Use this method, if you fed in the data using signUpdate. If you used the
   * sign(byte[]) method, you need not (and shall not) call this method,
   * because sign(byte[]) finalizes the signing operation itself.
   *
   * @return The final result of the signing operation; i.e. the signature
   *         value. Never returns {@code null}.
   * @throws PKCS11Exception
   *         If calculating the final signature value failed.
   */
  public byte[] signFinal(int maxSize)
      throws PKCS11Exception {
    return fixSignOutput(pkcs11.C_SignFinal(maxSize));
  }

  private byte[] fixSignOutput(byte[] orig) {
    if (signatureType == 0) {
      return orig;
    }

    synchronized (module) {
      if (signatureType == SIGN_TYPE_ECDSA) {
        Boolean b = module.getEcdsaSignatureFixNeeded();
        if (b == null) {
          LOG.info("EcdsaSignatureFixNeeded: null");
        } else {
          LOG.debug("EcdsaSignatureFixNeeded: {}", b);
        }

        if (b == null || b) {
          byte[] fixedSigValue;
          if (signVerifyExtraParams != null) {
            int rOrSLen = (signVerifyExtraParams.ecOrderBitSize() + 7) / 8;
            fixedSigValue = Functions.fixECDSASignature(orig,
                              rOrSLen);
          } else {
            // get the ecParams
            byte[] ecParams;
            try {
              ecParams = getAttrValues(signOrVerifyKeyHandle,
                  new AttributeTypes().ecParams()).ecParams();
            } catch (PKCS11Exception e) {
              LOG.debug("error getting CKA_EC_PARAMS for key {}",
                  signOrVerifyKeyHandle);
              return orig;
            }

            if (ecParams == null) {
              LOG.debug("found no CKA_EC_PARAMS for key {}",
                  signOrVerifyKeyHandle);
              return orig;
            }

            fixedSigValue = Functions.fixECDSASignature(orig, ecParams);
          }

          boolean fixed = !Arrays.equals(fixedSigValue, orig);
          if (b == null) {
            LOG.info("Set EcdsaSignatureFixNeeded to {}", fixed);
            module.setEcdsaSignatureFixNeeded(fixed);
          }
          return fixed ? fixedSigValue : orig;
        }
      } else if (signatureType == SIGN_TYPE_SM2) {
        Boolean b = module.getSm2SignatureFixNeeded();
        if (b == null) {
          LOG.info("Sm2SignatureFixNeeded: null");
        } else {
          LOG.debug("Sm2SignatureFixNeeded: {}", b);
        }

        if (b == null || b) {
          byte[] fixedSigValue = Functions.fixECDSASignature(orig, 32);
          boolean fixed = !Arrays.equals(fixedSigValue, orig);
          if (b == null) {
            LOG.info("Set Sm2SignatureFixNeeded to {}", fixed);
            module.setSm2SignatureFixNeeded(fixed);
          }
          return fixed ? fixedSigValue : orig;
        }
      }

      return orig;
    }
  }

  /**
   * Generate a new secret key or a set of domain parameters. It uses the set
   * attributes of the template for setting the attributes of the new key
   * object. As mechanism the application can use a constant of the Mechanism
   * class.
   *
   * @param mechanism
   *        The mechanism to generate a key for; e.g. Mechanism.DES to generate
   *        a DES key.
   * @param template
   *        The template for the new key or domain parameters; e.g. a
   *        DESSecretKey object which has set certain attributes.
   * @return The newly generated secret key or domain parameters.
   * @throws PKCS11Exception
   *         If generating a new secret key or domain parameters failed.
   */
  public long generateKey(CkMechanism mechanism, Template template)
      throws PKCS11Exception {
    long hKey = pkcs11.C_GenerateKey(toOutMechanism(mechanism),
                  toOutCKAttrs(template));
    traceObject("generated key", hKey);
    return hKey;
  }

  /**
   * Generate a new public key - private key key-pair and use the set
   * attributes of the template objects for setting the attributes of the new
   * public key and private key objects. As mechanism the application can use
   * a constant of the Mechanism class.
   *
   * @param mechanism
   *        The mechanism to generate a key for; e.g. Mechanism.RSA to generate
   *        a new RSA key-pair.
   * @param template
   *        The template for the new keypair.
   * @return The newly generated key-pair.
   * @throws PKCS11Exception
   *         If generating a new key-pair failed.
   */
  public PKCS11KeyPair generateKeyPair(
      CkMechanism mechanism, KeyPairTemplate template) throws PKCS11Exception {
    PKCS11KeyPair rv = pkcs11.C_GenerateKeyPair(
        toOutMechanism(mechanism), toOutCKAttrs(template.publicKey()),
        toOutCKAttrs(template.privateKey()));

    traceObject("public  key of the generated keypair",
        rv.getPublicKey());
    traceObject("private key of the generated keypair",
        rv.getPrivateKey());
    return rv;
  }

  private CkMechanism toOutMechanism(CkMechanism mechanism)
      throws PKCS11Exception {
    return mechanism.nativeCopy(token);
  }

  /**
   * Determines if this session is an R/W session.
   *
   * @return true if this is an R/W session, false otherwise.
   * @throws PKCS11Exception in case of error.
   */
  public boolean isRwSession() throws PKCS11Exception {
    if (this.rwSession == null) {
      this.rwSession = getSessionInfo().isRwSession();
    }

    return this.rwSession;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  @Override
  public String toString() {
    return "Session Handle: 0x" + Long.toHexString(pkcs11.hSession())
        + "\nToken: " + token;
  }

  public String getStringAttrValue(long hObject, long attrType)
      throws PKCS11Exception {
    return ((StringAttribute) doGetAttrValue(hObject, attrType)).getValue();
  }

  public Template getAttrValues(
      long hObject, AttributeTypes attributeTypes)
      throws PKCS11Exception {
    List<Long> attrTypes = new ArrayList<>(attributeTypes.size());

    // we need to fix attributes EC_PARAMS, where EC_PARAMS needs KEY_TYPE.
    long[] firstTypes = {CKA_CLASS, CKA_KEY_TYPE, CKA_EC_PARAMS};

    for (long type : firstTypes) {
      if (attributeTypes.remove(type)) {
        attrTypes.add(type);
      }
    }

    attrTypes.addAll(attributeTypes.getTypes());

    return doGetAttrValues(hObject, attrTypes);
  }

  /**
   * Return the default attributes, but without attributes which contain the
   * sensitive values.
   *
   * @param hObject
   *        the object handle.
   * @return the attributes.
   * @throws PKCS11Exception
   *         If getting attributes failed.
   */
  public Template getDefaultAttrValues(long hObject)
      throws PKCS11Exception {
    return getDefaultAttrValues(hObject, false);
  }

  /**
   * @param hObject
   *        the object handle.
   * @param withSensitiveAttributes
   *        whether to get the attributes which contain sensitive values.
   * Return the default attributes
   * @return the attributes.
   * @throws PKCS11Exception
   *         If getting attributes failed.
   */
  public Template getDefaultAttrValues(
      long hObject, boolean withSensitiveAttributes)
      throws PKCS11Exception {
    long objClass = getAttrValues(hObject,
        new AttributeTypes().class_()).class_();
    AttributeTypes ckaTypes = new AttributeTypes();
    ckaTypes.label().id().token();

    if (objClass == CKO_SECRET_KEY || objClass == CKO_PRIVATE_KEY) {
      ckaTypes.allowedMechanisms().decrypt().derive()
          .extractable().keyGenMechanism().neverExtractable()
          .private_().sign().unwrap().unwrapTemplate().wrapWithTrusted();

      Template attrs = getAttrValues(hObject,
          new AttributeTypes().keyType().sensitive().alwaysSensitive());
      long keyType = attrs.keyType();
      Boolean sensitive = attrs.sensitive();
      Boolean alwaysSensitive = attrs.alwaysSensitive();

      boolean withSensitiveAttrs = withSensitiveAttributes;
      if (withSensitiveAttrs) {
        boolean isSensitive = (sensitive == null) || sensitive;
        if (alwaysSensitive != null) {
          isSensitive |= alwaysSensitive;
        }
        withSensitiveAttrs = !isSensitive;
      }

      if (objClass == CKO_SECRET_KEY) {
        ckaTypes.encrypt().trusted().verify().wrap().wrapTemplate();

        if (!(keyType == CKK_DES || keyType == CKK_DES2
            || keyType == CKK_DES3)) {
          ckaTypes.valueLen();
        }

        if (withSensitiveAttrs) {
          ckaTypes.value();
        }
      } else {
        ckaTypes.alwaysAuthenticate().signRecover();

        if (keyType == CKK_RSA) {
          ckaTypes.modulus().publicExponent();
          if (withSensitiveAttrs) {
            ckaTypes.privateExponent().prime1().prime2()
                .exponent1().exponent2().coefficient();
          }
        } else if (keyType == CKK_EC || keyType == CKK_EC_EDWARDS
            || keyType == CKK_EC_MONTGOMERY || keyType == CKK_VENDOR_SM2) {
          ckaTypes.ecParams();
          if (withSensitiveAttrs) {
            ckaTypes.value();
          }
        } else if (keyType == CKK_DSA) {
          ckaTypes.prime().subprime().base();
          if (withSensitiveAttrs) {
            ckaTypes.value();
          }
        } else if (keyType == CKK_ML_DSA || keyType == CKK_ML_KEM) {
          ckaTypes.parameterSet();
          if (withSensitiveAttrs) {
            ckaTypes.seed();
            ckaTypes.value();
          }
        } else if (keyType == CKK_SLH_DSA) {
          ckaTypes.parameterSet();
          if (withSensitiveAttrs) {
            ckaTypes.value();
          }
        }
      }

      return getAttrValues(hObject, ckaTypes)
          .class_(objClass).keyType(keyType)
          .sensitive(sensitive).alwaysSensitive(alwaysSensitive);
    } else if (objClass == CKO_PUBLIC_KEY) {
      ckaTypes.allowedMechanisms().encrypt().keyGenMechanism().trusted()
          .verify().verifyRecover().wrap().wrapTemplate();
      long keyType = getAttrValues(hObject,
          new AttributeTypes().keyType()).keyType();
      if (keyType == CKK_RSA) {
        ckaTypes.modulus().publicExponent();
      } else if (keyType == CKK_EC
          || keyType == CKK_EC_EDWARDS
          || keyType == CKK_EC_MONTGOMERY
          || keyType == CKK_VENDOR_SM2) {
        ckaTypes.ecParams().ecPoint();
      } else if (keyType == CKK_DSA) {
        ckaTypes.prime().subprime().base();
      } else if (keyType == CKK_ML_DSA || keyType == CKK_ML_KEM
          || keyType == CKK_SLH_DSA) {
        ckaTypes.parameterSet().value();
      }

      return getAttrValues(hObject, ckaTypes)
          .class_(objClass).keyType(keyType);
    } else {
      return getAttrValues(hObject, ckaTypes);
    }
  }

  /* ********************************
   * V3.0 Functions
   * ********************************/

  /**
   * Logs in the user or the security officer to the session. Notice that all
   * sessions of a token have the same login state; i.e. if you log in the user
   * to one session all other open sessions of this token get user rights.
   *
   * @param userType
   *        CKU_SO for the security officer or CKU_USER to log in the user.
   * @param pin
   *        The PIN. The security officer-PIN or the user-PIN depending on the
   *        userType parameter.
   * @param username
   *        The username of the user.
   * @throws PKCS11Exception
   *         If login fails.
   */
  public void loginUser(long userType, byte[] pin, byte[] username)
      throws PKCS11Exception {
    pkcs11.C_LoginUser(userType, pin, username);
  }

  /**
   * terminates active session based operations.
   *
   * @throws PKCS11Exception If terminating operations failed
   */
  public void sessionCancel(long flags) throws PKCS11Exception {
    pkcs11.C_SessionCancel(flags);
  }

  /* ********************************
   * V3.2 Functions
   * ********************************/

  /**
   * Unwraps (decrypts) the given encrypted key with the unwrapping key using
   * the given mechanism. The application can also pass a template key to set
   * certain attributes of the unwrapped key. This creates a key object after
   * unwrapping the key and returns an object representing this key.
   *
   * @param mechanism
   *        The mechanism to use for unwrapping the key.
   * @param hPrivateKey
   *        The key to use for decapsulating.
   * @param encapsulatedKey
   *        The encrypted key to unwrap (decrypt).
   * @param keyTemplate
   *        The template for creating the new key object.
   * @return A key object representing the newly created key object.
   * @throws PKCS11Exception
   *         If unwrapping the key or creating a new key object failed.
   */
  public long decapsulateKey(CkMechanism mechanism, long hPrivateKey,
                             byte[] encapsulatedKey, Template keyTemplate)
      throws PKCS11Exception {
    long hKey = pkcs11.C_DecapsulateKey(toOutMechanism(mechanism),
        hPrivateKey, encapsulatedKey, toOutCKAttrs(keyTemplate));
    traceObject("decapsulated key", hKey);
    return hKey;
  }

  /* ********************************
   * Helper Functions
   * ********************************/

  /**
   * This method reads the attributes at once. This can lead  to performance
   * improvements. If reading all attributes at once fails, it tries to read
   * each attributes individually.
   *
   * @param hObject
   *        The handle of the object which contains the attributes.
   * @param attrTypes
   *        The attribute types
   * @exception PKCS11Exception
   *            If getting the attributes failed.
   */
  private Template doGetAttrValues(long hObject, List<Long> attrTypes)
      throws PKCS11Exception {
    Args.notNull(attrTypes, "attrTypes");

    if (attrTypes.size() == 1) {
      return new Template(doGetAttrValue(hObject, attrTypes.get(0)));
    }

    long[] types = new long[attrTypes.size()];
    for (int i = 0; i < types.length; i++) {
      types[i] = attrTypes.get(i);
    }

    Template template = pkcs11.C_GetAttributeValue(hObject, types);
    for (Attribute attr : template.attributes()) {
      postProcessGetAttribute(attr, hObject, template);
    }
    return template;
  }

  /**
   * This method reads the attribute specified by <code>attribute</code> from
   * the token using the given <code>session</code>.
   * The object from which to read the attribute is specified using the
   * <code>hObject</code>. The <code>attribute</code> will contain
   * the results.
   *
   * @param hObject
   *        The handle of the object which contains the attribute.
   * @param attrType
   *        The object specifying the attribute type
   * @exception PKCS11Exception
   *            If getting the attribute failed.
   */
  private Attribute doGetAttrValue(long hObject, long attrType)
      throws PKCS11Exception {
    return doGetAttrValue0(hObject, attrType, true);
  }

  private Attribute doGetAttrValue0(long hObject, final long attrType,
                                    boolean postProcess)
      throws PKCS11Exception {
    Template template = pkcs11.C_GetAttributeValue(
                            hObject, new long[]{attrType});
    Attribute attr = template.getAttribute(attrType);
    if (postProcess) {
      postProcessGetAttribute(attr, hObject, null);
    }
    return attr;
  }

  private Template toOutCKAttrs(Template template) {
    return toOutCKAttrs(template, true);
  }

  private Template toOutCKAttrs(
      Template attributes, boolean withNullValueAttr) {
    if (attributes == null) {
      return null;
    }

    for (Attribute attr : attributes.attributes()) {
      if (attr.isNullValue()) {
        continue;
      }

      long type = attr.type();
      if (type == CKA_KEY_TYPE) {
        long value = ((LongAttribute) attr).getValue();
        long vendorValue = module.genericToVendorCode(Category.CKK, value);
        if (value != vendorValue) {
          ((LongAttribute) attr).setValue(vendorValue);
        }
      } else if (type == CKA_EC_POINT) {
        byte[] value = ((ByteArrayAttribute) attr).getValue();
        ((ByteArrayAttribute) attr).setValue(Asn1Util.toOctetString(value));
      } else if (type == CKA_EC_PARAMS) {
        byte[] value = ((ByteArrayAttribute) attr).getValue();
        byte[] newPValue = null;
        if (module.hasSpecialBehaviour(
            SpecialBehaviour.EC_PARAMS_NAME_ONLY_EDWARDS)) {
          newPValue = Arrays.equals(OID_edwards25519, value) ? NAME_edwards25519
              : Arrays.equals(OID_edwards448, value) ? NAME_edwards448 : null;
        } else if (module.hasSpecialBehaviour(
            SpecialBehaviour.EC_PARAMS_NAME_ONLY_MONTGOMERY)) {
          newPValue = Arrays.equals(OID_curve25519, value) ? NAME_curve25519
              : Arrays.equals(OID_curve448, value) ? NAME_curve448 : null;
        }

        if (newPValue != null) {
          ((ByteArrayAttribute) attr).setValue(newPValue);
        }
      }
    }

    if (withNullValueAttr) {
      return attributes;
    }

    boolean hasNullValue = false;
    for (Attribute attr : attributes.attributes()) {
      if (attr.isNullValue()) {
        hasNullValue = true;
        break;
      }
    }

    if (!hasNullValue) {
      return attributes;
    }

    Template ret = new Template();
    for (Attribute attr : attributes.attributes()) {
      if (!attr.isNullValue()) {
        ret.attr(attr);
      }
    }

    return ret;
  }

  private void postProcessGetAttribute(
      Attribute attr, long hObject, Template otherAttrs) {
    long type = attr.type();

    if (type == CKA_EC_PARAMS) {
      ByteArrayAttribute bAttr = (ByteArrayAttribute) attr;
      if (bAttr.getValue() == null) {
        // Some HSMs do not return EC_PARAMS
        Long keyType = null;
        if (otherAttrs != null) {
          for (Attribute otherAttr : otherAttrs.attributes()) {
            if (type == otherAttr.type()) {
              continue;
            }

            if (otherAttr.type() == CKA_KEY_TYPE) {
              keyType = ((LongAttribute) otherAttr).getValue();
            }
          }
        }

        if (keyType == null) {
          try {
            keyType = getAttrValues(hObject,
                new AttributeTypes().keyType()).keyType();
          } catch (PKCS11Exception e2) {
          }
        }

        if (keyType != null && keyType == CKK_VENDOR_SM2) {
          ((ByteArrayAttribute) attr).setValue(
              Functions.decodeHex("06082a811ccf5501822d"));
        }
      } else {
        byte[] ecParams = bAttr.getValue();
        if (ecParams[0] != 0x06) { // 06: OBJECT IDENTIFIER
          bAttr.setValue(Functions.fixECParams(ecParams));
        }
      }

      return;
    }

    if (attr.value() == null) {
      return;
    }

    if (type == CKA_KEY_TYPE) {
      long value = ((LongAttribute) attr).getValue();
      ((LongAttribute) attr).setValue(
          module.vendorToGenericCode(Category.CKK, value));
    } else if (type == CKA_KEY_GEN_MECHANISM) {
      long value = ((LongAttribute) attr).getValue();
      ((LongAttribute) attr).setValue(
          module.vendorToGenericCode(Category.CKM, value));
    } else if (type == CKA_ALLOWED_MECHANISMS) {
      long[] mechanisms = ((LongArrayAttribute) attr).getValue();
      for (int i = 0; i < mechanisms.length; i++) {
        mechanisms[i] = module.vendorToGenericCode(Category.CKM, mechanisms[i]);
      }
    }
  }

  private void traceObject(String prefix, long hObject) {
    if (LOG.isTraceEnabled()) {
      try {
        LOG.trace("{}: handle={}, attributes\n{}", prefix, hObject,
            getDefaultAttrValues(hObject));
      } catch (PKCS11Exception e) {
        LOG.trace("{}: reading object {} failed with {}", prefix, hObject,
            e.getErrorName());
      }
    }
  }

}
