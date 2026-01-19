// Copyright (c) 2022-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.jni;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.attrs.Attribute;
import org.xipki.pkcs11.wrapper.attrs.Template;
import org.xipki.pkcs11.wrapper.params.CkParams;
import org.xipki.pkcs11.wrapper.params.NullParams;
import org.xipki.pkcs11.wrapper.type.CkInfo;
import org.xipki.pkcs11.wrapper.type.CkMechanism;
import org.xipki.pkcs11.wrapper.type.CkMechanismInfo;
import org.xipki.pkcs11.wrapper.type.CkSessionInfo;
import org.xipki.pkcs11.wrapper.type.CkSlotInfo;
import org.xipki.pkcs11.wrapper.type.CkTokenInfo;
import org.xipki.pkcs11.wrapper.type.CkVersion;

import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import static org.xipki.pkcs11.wrapper.jni.JniOperation.*;

/**
 * This class provides the PKCS#11 v2.40 functions.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class PKCS11 {

  private static final int REQUIRED = 1;
  private static final int OPTIONAL = 2;

  // attrs:  bit 8
  static final int ATTRS_R = REQUIRED << 8;
  // attrs2: bit 9
  static final int ATTRS2_R = REQUIRED << 9;

  // mechParams: bits 10-11
  static final int METH_R = REQUIRED << 10;
  static final int METH_O = OPTIONAL << 10;

  // data: bits 12-13
  static final int DATA_R = REQUIRED << 12;
  static final int DATA_O = OPTIONAL << 12;

  // data: bits 14-15
  static final int DATA2_R = REQUIRED << 14;
  static final int DATA2_O = OPTIONAL << 14;

  public static final int MAX_SIZE_NULL = 0x7FFFFFFF;

  private final Object syncObj = new Object();

  private static final Logger log = LoggerFactory.getLogger(PKCS11.class);

  private final static Set<Integer> moduleIds = new HashSet<>();

  protected int moduleId;

  protected abstract Arch arch();

  protected abstract void initModule(int moduleId, String modulePath)
      throws PKCS11Exception;

  protected abstract void closeModule(int moduleId)
      throws PKCS11Exception;

  protected abstract byte[] doQuery(
      int moduleId, int opCode, byte[] resp,
      long id, long id2, long id3, int size,
      byte[] data, byte[] data2,
      long ckm, byte[] mechParams,
      byte[] template, byte[] template2);

  public abstract CkVersion getVersion(int moduleId) throws PKCS11Exception;

  /* *****************************
   * cryptoki v2.x Functions
   * *****************************/

  /**
   * C_Initialize initializes the Cryptoki library. (General-purpose)
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_Initialize)
   * (
   *   CK_VOID_PTR   pInitArgs
   * )
   * </pre>
   * @param flags
   *        flags to initialize a module.
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_Initialize(long flags) throws PKCS11Exception {
    synchronized (syncObj) {
      QueryParams qParams = new QueryParams(C_Initialize).flags(flags);
      query(qParams);
    }
  }

  /**
   * C_Finalize indicates that an application is done with the Cryptoki library
   * (General-purpose).
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_Finalize)
   * (
   *   CK_VOID_PTR   pReserved  // reserved.  Should be NULL_PTR
   * );
   * </pre>
   *
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_Finalize() throws PKCS11Exception {
    synchronized (syncObj) {
      QueryParams qParams = new QueryParams(C_Finalize);
      query(qParams);
    }
  }

  /**
   * C_GetInfo returns general information about Cryptoki. (General-purpose)
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_GetInfo)
   * (
   *   CK_INFO_PTR   pInfo
   * )
   * </pre>
   * @return the information.
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public CkInfo C_GetInfo() throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_GetInfo);
    return query(qParams).infoPayload();
  }

  /**
   * C_GetSlotList obtains a list of slots in the system.
   * (Slot and token management)
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_GetSlotList)
   * (
   *   CK_BBOOL       tokenPresent,  // only slots with tokens
   *   CK_SLOT_ID_PTR pSlotList,     // receives array of slot IDs
   *   CK_ULONG_PTR   pulCount       // receives number of slots
   * );
   * </pre>
   *
   * @param tokenPresent
   *        if true only Slot IDs with a token are returned
   * @return a long array of slot IDs and number of Slot IDs
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public long[] C_GetSlotList(boolean tokenPresent) throws PKCS11Exception {
    long flags = tokenPresent ? 1 : 0;
    QueryParams qParams = new QueryParams(C_GetSlotList).flags(flags);
    return query(qParams).longArrayPayload();
  }

  /**
   * C_GetSlotInfo obtains information about a particular slot in the system.
   * (Slot and token management)
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_GetSlotInfo)
   * (
   *   CK_SLOT_ID       slotID,  // the ID of the slot
   *   CK_SLOT_INFO_PTR pInfo    // receives the slot information
   * );
   * </pre>
   *
   * @param slotID
   *        the ID of the slot
   * @return the slot information
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public CkSlotInfo C_GetSlotInfo(long slotID) throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_GetSlotInfo, slotID);
    return query(qParams).slotInfoPayload();
  }

  /**
   * C_GetTokenInfo obtains information about a particular token in the system.
   * (Slot and token management)
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_GetTokenInfo)
   * (
   *   CK_SLOT_ID        slotID,  // ID of the token's slot
   *   CK_TOKEN_INFO_PTR pInfo    // receives the token information
   * );
   * </pre>
   *
   * @param slotID
   *        ID of the token's slot
   * @return the token information
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public CkTokenInfo C_GetTokenInfo(long slotID) throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_GetTokenInfo, slotID);
    return query(qParams).tokenInfoPayload();
  }

  /**
   * C_GetMechanismList obtains a list of mechanism types supported by a token.
   * (Slot and token management)
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_GetMechanismList)
   * (
   *   CK_SLOT_ID            slotID,          // ID of token's slot
   *   CK_MECHANISM_TYPE_PTR pMechanismList,  // gets mech. array
   *   CK_ULONG_PTR          pulCount         // gets # of mechs.
   * );
   * </pre>
   *
   * @param slotID
   *        ID of the token's slot
   * @return a long array of mechanism types and number of mechanism types
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public long[] C_GetMechanismList(long slotID) throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_GetMechanismList, slotID);
    return query(qParams).longArrayPayload();
  }

  /**
   * C_GetMechanismInfo obtains information about a particular mechanism
   * possibly supported by a token. (Slot and token management)
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_GetMechanismInfo)
   * (
   *   CK_SLOT_ID            slotID,  // ID of the token's slot
   *   CK_MECHANISM_TYPE     type,    // type of mechanism
   *   CK_MECHANISM_INFO_PTR pInfo    // receives mechanism info
   * );
   * </pre>
   *
   * @param slotID
   *        ID of the token's slot
   * @param type
   *        type of mechanism
   * @return the mechanism info
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   *
   */
  public CkMechanismInfo C_GetMechanismInfo(long slotID, long type)
      throws PKCS11Exception {
    QueryParams params = new QueryParams(C_GetMechanismInfo, slotID).id2(type);
    return query(params).mechanismInfoPayload();
  }

  /* *****************************
   * Session management
   * *****************************/

  /**
   * C_OpenSession opens a session between an application and a token.
   * (Session management)
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_OpenSession)
   * (
   *   CK_SLOT_ID            slotID,        // the slot's ID
   *   CK_FLAGS              flags,         // from CK_SESSION_INFO
   *   CK_VOID_PTR           pApplication,  // passed to callback
   *   CK_NOTIFY             Notify,        // callback function
   *   CK_SESSION_HANDLE_PTR phSession      // gets session handle
   * );
   * </pre>
   *
   * @param slotID
   *        the slot's ID
   * @param flags
   *        of CK_SESSION_INFO
   * @return the session handle
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public long C_OpenSession(long slotID, long flags) throws PKCS11Exception {
    synchronized (syncObj) {
      QueryParams qParams = new QueryParams(C_OpenSession, slotID).flags(flags);
      return query(qParams).longPayload();
    }
  }

  /**
   * C_CloseSession closes a session between an application and a token.
   * (Session management)
   *
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_CloseSession)
   * (
   *   CK_SESSION_HANDLE hSession  // the session's handle
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_CloseSession(long hSession) throws PKCS11Exception {
    synchronized (syncObj) {
      QueryParams qParams = new QueryParams(C_CloseSession, hSession);
      query(qParams);
    }
  }

  /**
   * C_CloseAllSessions closes all sessions with a token. (Session management)
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_CloseAllSessions)
   * (
   *   CK_SLOT_ID     slotID  // the token's slot
   * );
   * </pre>
   * @param slotID
   *        the ID of the token's slot
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_CloseAllSessions(long slotID) throws PKCS11Exception {
    synchronized (syncObj) {
      QueryParams qParams = new QueryParams(C_CloseAllSessions, slotID);
      query(qParams);
    }
  }

  /**
   * C_GetSessionInfo obtains information about the session.
   * (Session management)
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_GetSessionInfo)
   * (
   *   CK_SESSION_HANDLE   hSession,  // the session's handle
   *   CK_SESSION_INFO_PTR pInfo      // receives session info
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @return the session info
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public CkSessionInfo C_GetSessionInfo(long hSession) throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_GetSessionInfo, hSession);
    return query(qParams).sessionInfoPayload();
  }

  /**
   * C_Login logs a user into a token. (Session management)
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_Login)
   * (
   *   CK_SESSION_HANDLE hSession,  // the session's handle
   *   CK_USER_TYPE      userType,  // the user type
   *   CK_UTF8CHAR_PTR   pPin,      // the user's PIN
   *   CK_ULONG          ulPinLen   // the length of the PIN
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @param userType
   *        the user type
   * @param pin
   *        the user's PIN and the length of the PIN
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_Login(long hSession, long userType, byte[] pin)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_Login, hSession)
        .data(pin).id2(userType);
    query(qParams);
  }

  /**
   * C_Logout logs a user out from a token. (Session management)
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_Logout)
   * (
   *   CK_SESSION_HANDLE hSession  // the session's handle
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_Logout(long hSession) throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_Logout, hSession);
    query(qParams);
  }

  /* *******************************
   * Object management
   * *******************************/

  /**
   * C_CreateObject creates a new object. (Object management)
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_CreateObject)
   * (
   *   CK_SESSION_HANDLE hSession,    // the session's handle
   *   CK_ATTRIBUTE_PTR  pTemplate,   // the object's template
   *   CK_ULONG          ulCount,     // attributes in template
   *   CK_OBJECT_HANDLE_PTR phObject  // gets new object's handle.
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @param template
   *        the object's template and number of attributes in template
   * @return the object's handle
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public long C_CreateObject(long hSession, Template template)
      throws PKCS11Exception {
    QueryParams params = new QueryParams(C_CreateObject, hSession)
        .template(template);
    return query(params).longPayload();
  }

  /**
   * C_CopyObject copies an object, creating a new object for the copy.
   * (Object management)
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_CopyObject)
   * (
   *   CK_SESSION_HANDLE    hSession,    // the session's handle
   *   CK_OBJECT_HANDLE     hObject,     // the object's handle
   *   CK_ATTRIBUTE_PTR     pTemplate,   // template for new object
   *   CK_ULONG             ulCount,     // attributes in template
   *   CK_OBJECT_HANDLE_PTR phNewObject  // receives handle of copy
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @param hObject
   *        the object's handle
   * @param template
   *        the template for the new object and number of attributes in template
   * @return the handle of the copy
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public long C_CopyObject(long hSession, long hObject, Template template)
      throws PKCS11Exception {
    QueryParams params = new QueryParams(C_CreateObject, hSession)
                .id2(hObject).template(template);
    return query(params).longPayload();
  }

  /**
   * C_DestroyObject destroys an object. (Object management)
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_DestroyObject)
   * (
   *   CK_SESSION_HANDLE hSession,  // the session's handle
   *   CK_OBJECT_HANDLE  hObject    // the object's handle
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @param hObject
   *        the object's handle
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_DestroyObject(long hSession, long hObject)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_DestroyObject, hSession)
        .id2(hObject);
    query(qParams);
  }

  /**
   * C_GetAttributeValue obtains the value of one or more object attributes.
   * (Object management) note: in PKCS#11 pTemplate and the result template
   * are the same
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_GetAttributeValue)
   * (
   *   CK_SESSION_HANDLE hSession,   // the session's handle
   *   CK_OBJECT_HANDLE  hObject,    // the object's handle
   *   CK_ATTRIBUTE_PTR  pTemplate,  // specifies attrs; gets vals
   *   CK_ULONG          ulCount     // attributes in template
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @param hObject
   *        the object's handle
   * @param types
   *        Specifies the types of attributes to get.
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public Template C_GetAttributeValue(long hSession, long hObject, long[] types)
      throws PKCS11Exception {
    int numTemplateCkas = 0;
    for (long type : types) {
      if (Attribute.getDataType(type) == Attribute.DataType.CkTemplate) {
        numTemplateCkas++;
      }
    }

    long[] simpleTypes;
    long[] templateTypes;
    if (numTemplateCkas == 0) {
      simpleTypes = types;
      templateTypes = null;
    } else if (numTemplateCkas == types.length) {
      simpleTypes = null;
      templateTypes = types;
    } else {
      simpleTypes = new long[types.length - numTemplateCkas];
      templateTypes = new long[numTemplateCkas];
      int si = 0;
      int ti = 0;
      for (long type : types) {
        if (Attribute.getDataType(type) == Attribute.DataType.CkTemplate) {
          templateTypes[ti++] = type;
        } else {
          simpleTypes[si++] = type;
        }
      }
    }

    Arch arch = arch();
    Template ret;
    if (simpleTypes == null) {
      ret = new Template();
    } else {
      byte[] data1 = JniUtil.encodeLongs(arch, simpleTypes);
      QueryParams params = new QueryParams(C_GetAttributeValue, hSession)
          .data(data1).id2(hObject);
      JniResult res = query(params);
      ret = res.templatePayload();
      long ckr = ((JniResp.JniLongResp) res.resp()).value();
      int numNull = 0;

      for (long type : types) {
        Attribute attr = ret.getAttribute(type);
        if (attr == null) {
          attr = Attribute.getInstance(type);
          ret.attr(attr);
        }

        if (attr.isNullValue()) {
          numNull++;
          if (ckr == PKCS11T.CKR_ATTRIBUTE_SENSITIVE) {
            attr.sensitive(true);
          }
        }
      }

      if (numNull > 1) {
        // get the attribute one-by-one
        for (long type : types) {
          Attribute attr = ret.getAttribute(type);
          if (!attr.isNullValue()) {
            continue;
          }

          params = new QueryParams(C_GetAttributeValue, hSession)
              .data(JniUtil.encodeLong(arch, type)).id2(hObject);
          JniResult res2 = query(params);
          if (res2.hasPayload()) {
            Attribute attr2 = res2.templatePayload().getAttribute(type);
            if (attr2 != null) {
              ret.remove(type);
              ret.attr(attr2);
            }
          } else {
            long ckr2 = ((JniResp.JniLongResp) res2.resp()).value();
            attr.sensitive(ckr2 == PKCS11T.CKR_ATTRIBUTE_SENSITIVE);
          }
        }
      }
    }

    if (templateTypes != null) {
      for (long type : templateTypes) {
        QueryParams params = new QueryParams(C_GetAttributeValueX, hSession)
                .id2(hObject).id3(type);
        JniResult res = query(params);
        if (res.hasPayload()) {
          ret.attr(type, res.templatePayload());
        } else {
          Attribute attr = Attribute.getInstance(type);
          ret.attr(attr);
        }
      }
    }

    for (long type : types) {
      if (!ret.hasAttribute(type)) {
        ret.attr(Attribute.getInstance(type));
      }
    }
    return ret;
  }

  /**
   * C_SetAttributeValue modifies the value of one or more object attributes
   * (Object management).
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_SetAttributeValue)
   * (
   *   CK_SESSION_HANDLE hSession,   // the session's handle
   *   CK_OBJECT_HANDLE  hObject,    // the object's handle
   *   CK_ATTRIBUTE_PTR  pTemplate,  // specifies attrs and values
   *   CK_ULONG          ulCount     // attributes in template
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @param hObject
   *        the object's handle
   * @param template
   *        specifies the attributes and values to get; number of attributes
   *        in the template
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_SetAttributeValue(long hSession, long hObject,
                                  Template template)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_SetAttributeValue, hSession)
              .id2(hObject).template(template);
    query(qParams);
  }

  /**
   * C_FindObjectsInit initializes a search for token and session objects
   * that match a template. (Object management)
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_FindObjectsInit)
   * (
   *   CK_SESSION_HANDLE hSession,   // the session's handle
   *   CK_ATTRIBUTE_PTR  pTemplate,  // attribute values to match
   *   CK_ULONG          ulCount     // attrs in search template
   * );
   * </pre>
   * @param hSession
   *        the session's handle
   * @param template
   *        the object's attribute values to match and the number of attributes
   *        in search template
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_FindObjectsInit(long hSession, Template template)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_FindObjectsInit, hSession)
        .template(template);
    query(qParams);
  }

  /**
   * C_FindObjects continues a search for token and session objects that
   * match a template, obtaining additional object handles.
   * (Object management)
   *
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_FindObjects)
   * (
   *  CK_SESSION_HANDLE    hSession,          // session's handle
   *  CK_OBJECT_HANDLE_PTR phObject,          // gets obj. handles
   *  CK_ULONG             ulMaxObjectCount,  // max handles to get
   *  CK_ULONG_PTR         pulObjectCount     // actual # returned
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @param maxObjectCount
   *        the max. object handles to get
   * @return the object's handles and the actual number of objects returned
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public long[] C_FindObjects(long hSession, int maxObjectCount)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_FindObjects, hSession)
                .size(maxObjectCount);
    return query(qParams).longArrayPayload();
  }

  /**
   * C_FindObjectsFinal finishes a search for token and session objects.
   * (Object management)
   *
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_FindObjectsFinal)
   * (
   *   CK_SESSION_HANDLE hSession  // the session's handle
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_FindObjectsFinal(long hSession) throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_FindObjectsFinal, hSession);
    query(qParams);
  }

  /* ********************************
   * Encryption and decryption
   * ********************************/

  /* ******************************
   * Message digesting
   * ******************************/

  /**
   * C_DigestInit initializes a message-digesting operation.
   * (Message digesting)
   *
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_DigestInit)
   * (
   *   CK_SESSION_HANDLE hSession,   // the session's handle
   *   CK_MECHANISM_PTR  pMechanism  // the digesting mechanism
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @param mechanism
   *        the digesting mechanism
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_DigestInit(long hSession, CkMechanism mechanism)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_DigestInit, hSession)
        .mech(mechanism);
    query(qParams);
  }

  /**
   * C_Digest digests data in a single part. (Message digesting)
   *
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_Digest)
   * (
   *   CK_SESSION_HANDLE hSession,     // the session's handle
   *   CK_BYTE_PTR       pData,        // data to be digested
   *   CK_ULONG          ulDataLen,    // bytes of data to digest
   *   CK_BYTE_PTR       pDigest,      // gets the message digest
   *   CK_ULONG_PTR      pulDigestLen  // gets digest length
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @param data
   *        the data to get digested and the data's length
   * @param maxSize
   *        the maximal size of the digest.
   * @return the message digest and the length of the message digest
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public byte[] C_Digest(long hSession, byte[] data, int maxSize)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_Digest, hSession)
        .data(data).size(maxSize);
    return query(qParams).payload();
  }

  /**
   * C_DigestUpdate continues a multiple-part message-digesting operation.
   * (Message digesting)
   *
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_DigestUpdate)
   * (
   *   CK_SESSION_HANDLE hSession,  // the session's handle
   *   CK_BYTE_PTR       pPart,     // data to be digested
   *   CK_ULONG          ulPartLen  // bytes of data to be digested
   * );
   * </pre>
   * @param hSession
   *        the session's handle
   * @param part
   *        the data to get digested and the data's length
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_DigestUpdate(long hSession, byte[] part)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_DigestUpdate, hSession).data(part);
    query(qParams);
  }

  /**
   * C_DigestKey continues a multipart message-digesting operation, by
   * digesting the value of a secret key as part of the data already digested.
   * (Message digesting)
   *
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_DigestKey)
   * (
   *   CK_SESSION_HANDLE hSession,  // the session's handle
   *   CK_OBJECT_HANDLE  hKey       // secret key to digest
   * );
   * </pre>
   * @param hSession
   *        the session's handle
   * @param hKey
   *        the handle of the secret key to be digested
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_DigestKey(long hSession, long hKey) throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_DigestKey, hSession).id2(hKey);
    query(qParams);
  }

  /**
   * C_DigestFinal finishes a multiple-part message-digesting operation.
   * (Message digesting)
   *
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_DigestFinal)
   * (
   *   CK_SESSION_HANDLE hSession,     // the session's handle
   *   CK_BYTE_PTR       pDigest,      // gets the message digest
   *   CK_ULONG_PTR      pulDigestLen  // gets byte count of digest
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @param maxSize
   *        the maximal size of the digest.
   * @return the message digest and the length of the message digest
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public byte[] C_DigestFinal(long hSession, int maxSize)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_DigestFinal, hSession)
        .size(maxSize);
    return query(qParams).payload();
  }

  /* **************************
   * Sign and MAC
   * **************************/

  /**
   * C_SignInit initializes a signature (private key encryption) operation,
   * where the signature is (will be) an appendix to the data, and plaintext
   * cannot be recovered from the signature.
   * (Sign and MAC)
   *
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_SignInit)
   * (
   *   CK_SESSION_HANDLE hSession,    // the session's handle
   *   CK_MECHANISM_PTR  pMechanism,  // the signature mechanism
   *   CK_OBJECT_HANDLE  hKey         // handle of signature key
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @param mechanism
   *        the signature mechanism
   * @param hKey
   *        the handle of the signature key
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_SignInit(long hSession, CkMechanism mechanism, long hKey)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_SignInit, hSession)
        .id2(hKey).mech(mechanism);
    query(qParams);
  }

  /**
   * C_Sign signs (encrypts with private key) data in a single part, where
   * the signature is (will be) an appendix to the data, and plaintext cannot
   * be recovered from the signature.
   * (Sign and MAC)
   *
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_Sign)
   * (
   *   CK_SESSION_HANDLE hSession,        // the session's handle
   *   CK_BYTE_PTR       pData,           // the data to sign
   *   CK_ULONG          ulDataLen,       // count of bytes to sign
   *   CK_BYTE_PTR       pSignature,      // gets the signature
   *   CK_ULONG_PTR      pulSignatureLen  // gets signature length
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @param data
   *        the data to sign and the data's length
   * @param maxSize
   *        the maximal size of the signature.
   * @return the signature and the signature's length
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public byte[] C_Sign(long hSession, byte[] data, int maxSize)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_Sign, hSession)
        .data(data).size(maxSize);
    return query(qParams).payload();
  }

  /**
   * C_SignUpdate continues a multiple-part signature operation, where the
   * signature is (will be) an appendix to the data, and plaintext cannot be
   * recovered from the signature.
   * (Sign and MAC)
   *
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_SignUpdate)
   * (
   *   CK_SESSION_HANDLE hSession,  // the session's handle
   *   CK_BYTE_PTR       pPart,     // the data to sign
   *   CK_ULONG          ulPartLen  // count of bytes to sign
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @param part
   *        the data part to sign and the data part's length
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_SignUpdate(long hSession, byte[] part)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_SignUpdate, hSession).data(part);
    query(qParams);
  }

  /**
   * C_SignFinal finishes a multiple-part signature operation, returning the
   * signature. (Sign and MAC)
   *
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_SignFinal)
   * (
   *   CK_SESSION_HANDLE hSession,        // the session's handle
   *   CK_BYTE_PTR       pSignature,      // gets the signature
   *   CK_ULONG_PTR      pulSignatureLen  // gets signature length
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @param maxSize
   *        the maximal size of the signature.
   * @return the signature and the signature's length
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public byte[] C_SignFinal(long hSession, int maxSize)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_SignFinal, hSession)
        .size(maxSize);
    return query(qParams).payload();
  }

  /* *****************************************
   * Dual-function cryptographic operations  *
   * *****************************************/

  /* **************************************
   * Key management
   * **************************************/

  /**
   * C_GenerateKey generates a secret key, creating a new key object.
   * (Key management)
   *
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_GenerateKey)
   * (
   *   CK_SESSION_HANDLE    hSession,    // the session's handle
   *   CK_MECHANISM_PTR     pMechanism,  // key generation mech.
   *   CK_ATTRIBUTE_PTR     pTemplate,   // template for new key
   *   CK_ULONG             ulCount,     // # of attrs in template
   *   CK_OBJECT_HANDLE_PTR phKey        // gets handle of new key
   * );
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @param mechanism
   *        the key generation mechanism
   * @param template
   *        the template for the new key and the number of attributes in the
   *        template
   * @return the handle of the new key
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public long C_GenerateKey(
      long hSession, CkMechanism mechanism, Template template)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_GenerateKey, hSession)
                .mech(mechanism).template(template);
    return query(qParams).longPayload();
  }

  /**
   * C_GenerateKeyPair generates a native-key/private-key pair, creating new
   * key objects.
   * (Key management)
   *
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_GenerateKeyPair)
   * (
   *   CK_SESSION_HANDLE    hSession,                  // session handle
   *   CK_MECHANISM_PTR     pMechanism,                // key-gen mech.
   *   CK_ATTRIBUTE_PTR     pPublicKeyTemplate,        // template for pub. key
   *   CK_ULONG             ulPublicKeyAttributeCount, // # pub. attrs.
   *   CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,      // template for priv. key
   *   CK_ULONG             ulPrivateKeyAttributeCount, // # priv.  attrs.
   *   CK_OBJECT_HANDLE_PTR phPublicKey,               // gets pub. key handle
   *   CK_OBJECT_HANDLE_PTR phPrivateKey               // gets priv. key handle
   * );
   * </pre>
   * @param hSession
   *        the session's handle
   * @param mechanism
   *        the key generation mechanism
   * @param publicKeyTemplate
   *        the template for the new key and the number of attributes in the
   *        template
   * @param privateKeyTemplate
   *        the template for the new private key and the number of attributes
   *        in the template
   * @return a long array with exactly two elements and the key handle as the
   *         first element and the private key handle as the second element
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public long[] C_GenerateKeyPair(
      long hSession, CkMechanism mechanism,
      Template publicKeyTemplate, Template privateKeyTemplate)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_GenerateKeyPair, hSession)
                .mech(mechanism).template(publicKeyTemplate)
                .template2(privateKeyTemplate);
    return query(qParams).longArrayPayload();
  }

  /* *****************************
   * cryptoki v3.0 Functions
   * *****************************/

  /**
   * C_LoginUser logs a user into a token. (Session management)
   *
   * <pre>
   * CK_DECLARE_FUNCTION(CK_RV, C_LoginUser)(
   *    CK_SESSION_HANDLE  hSession,
   *    CK_USER_TYPE       userType,
   *    CK_UTF8CHAR_PTR    pPin,
   *    CK_ULONG           ulPinLen,
   *    CK_UTF8CHAR_PTR    pUsername,
   *    CK_ULONG ulUsernameLen);
   * </pre>
   *
   * @param hSession
   *        the session's handle
   * @param userType
   *        the user type
   * @param pin
   *        the user's PIN and the length of the PIN
   * @param username
   *        the username and the length of the username
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_LoginUser(long hSession, long userType, byte[] pin,
                          byte[] username)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_LoginUser, hSession)
        .id2(userType).data(pin).data2(username);
    query(qParams);
  }

  /**
   * C_SessionCancel terminates active session based operations
   * (Session management).
   * <pre>
   * CK_PKCS11_FUNCTION_INFO(C_SessionCancel)
   * (
   *   CK_SESSION_HANDLE hSession, // the session's handle
   *   CK_FLAGS          flags     // flags control which sessions are cancelled
   * );
   * </pre>
   * @param hSession
   *        the session's handle
   * @param flags
   *        indicates which operations should be cancelled
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public void C_SessionCancel(long hSession, long flags)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_SessionCancel, hSession)
        .flags(flags);
    query(qParams);
  }

  /* *****************************
   * cryptoki v3.2 Functions
   * *****************************/

  /**
   * <pre>
   * CK_DECLARE_FUNCTION(CK_RV, C_DecapsulateKey)(
   *   CK_SESSION_HANDLE     hSession,
   *   CK_MECHANISM_PTR      pMechanism,
   *   CK_OBJECT_HANDLE      hPrivateKey,
   *   CK_ATTRIBUTE_PTR      pTemplate,
   *   CK_ULONG              ulAttributeCount,
   *   CK_BYTE_PTR           pCiphertext,
   *   CK_ULONG              ulCiphertextLen,
   *   CK_OBJECT_HANDLE_PTR  phKey,
   * );
   * </pre>
   * @param hSession the session handle
   * @param mechanism the mechanism
   * @param hPrivateKey the private key (decapsulating key)
   * @param template the template of new key in the device
   * @return the handle pointed to the decapsulated key in PKCS#11 device.
   * @throws PKCS11Exception
   *         If function returns other value than CKR_OK.
   */
  public long C_DecapsulateKey(
      long hSession, CkMechanism mechanism, long hPrivateKey,
      byte[] cipherText, Template template)
      throws PKCS11Exception {
    QueryParams qParams = new QueryParams(C_DecapsulateKey, hSession)
        .data(cipherText).id2(hPrivateKey).mech(mechanism).template(template);
    return query(qParams).longPayload();
  }

  public void initModule(String modulePath) throws PKCS11Exception {
    int mid;
    Random rnd = new Random();
    do {
      mid = rnd.nextInt();
      if (mid < 0) {
        mid *= -1;
      }
    } while (mid == 0 || moduleIds.contains(mid));

    initModule(mid, modulePath);
    CkVersion version = getVersion(mid);
    log.info("cryptoki version for {} is {}", modulePath, version);

    this.moduleId = mid;
    moduleIds.add(mid);
  }

  public void closeModule() {
    try {
      closeModule(moduleId);
    } catch (Throwable t) {
      log.error("closing module {} failed", moduleId, t);
    }
    this.moduleId = 0;
  }

  protected JniResult query(QueryParams params) throws PKCS11Exception {
    Arch arch = arch();
    long ckm = 0;

    byte[] mechParamsBytes = null;
    CkParams mechParams = params.mechParams;
    if (mechParams != null) {
      ckm = params.mechCode;
      mechParamsBytes = mechParams.getEncoded(arch);
    }

    byte[] templateBytes = params.template == null ? null
        : params.template.getEncoded(arch);
    byte[] template2Bytes = params.template2 == null ? null
        : params.template2.getEncoded(arch);

    byte[] payload = doQuery(moduleId, params.op.getCode(), params.resp,
        params.id, params.id2, params.id3, params.size, params.data,
        params.data2, ckm, mechParamsBytes, templateBytes, template2Bytes);

    JniResp resp = JniResp.decodeSucc(arch, params.resp);
    return new JniResult(arch, resp, payload);
  }

  class QueryParams {
    final JniOperation op;
    final byte[] resp;
    final long id;
    long id2;
    long id3;
    int size;
    byte[] data;
    byte[] data2;
    long mechCode;
    CkParams mechParams;

    Template template;
    Template template2;

    QueryParams(JniOperation op) {
      this(op, 0);
    }

    QueryParams(JniOperation op, long id) {
      this.op = op;
      this.id = id;
      this.resp = new byte[1 + arch().longSize()];
    }

    public QueryParams id2(long id2) {
      this.id2 = id2;
      return this;
    }

    public QueryParams flags(long flags) {
      return id2(flags);
    }

    public QueryParams id3(long id3) {
      this.id3 = id3;
      return this;
    }

    public QueryParams size(int size) {
      this.size = size;
      return this;
    }

    public QueryParams data(byte[] data) {
      this.data = data;
      return this;
    }

    public QueryParams data2(byte[] data2) {
      this.data2 = data2;
      return this;
    }

    public QueryParams mech(CkMechanism mechanism) {
      this.mechCode = mechanism.getMechanism();
      return mechParams(mechanism.getParameters());
    }

    public QueryParams mechParams(CkParams ckParams) {
      this.mechParams = ckParams != null ? ckParams : NullParams.INSTANCE;
      return this;
    }

    public QueryParams template(Template template) {
      this.template = template == null ? new Template() : template;
      return this;
    }

    public QueryParams template2(Template template2) {
      this.template2 = template2 == null ? new Template() : template2;
      return this;
    }
  }

}
