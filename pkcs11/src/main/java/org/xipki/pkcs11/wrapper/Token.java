// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.type.CkMechanismInfo;
import org.xipki.pkcs11.wrapper.type.CkTokenInfo;
import org.xipki.util.codec.Args;

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_RW_SESSION;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_SERIAL_SESSION;

/**
 * Objects of this class represent PKCS#11 tokens.
 *
 * @author Lijun Liao (xipki)
 */
public class Token {

  private static final Logger LOG = LoggerFactory.getLogger(Token.class);

  /**
   * The reference to the slot.
   */
  private final Slot slot;

  /**
   * The identifier of the slot.
   */
  private final long slotID;

  private final Object loginSync;

  private final long[] mechCodes;

  private final Map<Long, CkMechanismInfo> mechCodeInfoMap = new HashMap<>();

  /**
   * @param slot The reference to the slot.
   */
  protected Token(Slot slot) {
    this.slot   = Args.notNull(slot, "slot");
    this.slotID = slot.getSlotID();
    this.loginSync = "loginSync-slotID_" + slotID + "-" + Instant.now();

    PKCS11Module module = slot.getModule();
    long[] nativeMechanisms;
    try {
      nativeMechanisms = module.getPKCS11().C_GetMechanismList(slotID);
    } catch (PKCS11Exception ex) {
      LOG.warn("error calling C_GetMechanismList: {}",
          ex.getMessage());
      mechCodes = new long[0];
      return;
    }

    Map<Long, CkMechanismInfo> nativeMechCodeInfoMap = new HashMap<>();
    for (long ckm : nativeMechanisms) {
      CkMechanismInfo mechInfo;
      try {
        mechInfo = module.getPKCS11().C_GetMechanismInfo(slotID, ckm);
      } catch (PKCS11Exception ex) {
        LOG.warn(
            "error calling C_GetMechanismInfo for mechanism {}: {}",
            PKCS11T.ckmCodeToName(ckm), ex.getMessage());
        continue;
      }

      mechInfo = module.adaptMechanismFlags(ckm, mechInfo);
      nativeMechCodeInfoMap.put(ckm, mechInfo);
    }

    Set<Long> mechCodeSet = new HashSet<>();
    for (long mechCode : nativeMechanisms) {
      mechCodeSet.add(mechCode);
    }

    for (long code : mechCodeSet) {
      if (mechCodeInfoMap.containsKey(code)) {
        continue;
      }

      CkMechanismInfo info = nativeMechCodeInfoMap.get(code);
      long code2 = module.vendorToGenericCode(Category.CKM, code);
      mechCodeInfoMap.put(code2, info);
    }

    Set<Long> mechCodeSet2 = mechCodeInfoMap.keySet();
    mechCodes = new long[mechCodeSet2.size()];
    int i = 0;
    for (long code : mechCodeSet2) {
      mechCodes[i++] = code;
    }
  }

  Object getLoginSync() {
    return loginSync;
  }

  /**
   * Get the slot that created this Token object.
   *
   * @return The slot of this token.
   */
  public Slot getSlot() {
    return slot;
  }

  /**
   * Get the ID of this token. This is the ID of the slot this token resides in.
   *
   * @return The ID of this token.
   */
  public long getTokenID() {
    return slotID;
  }

  /**
   * Get information about this token.
   *
   * @return An object containing information about this token.
   * @exception PKCS11Exception
   *            If reading the information fails.
   */
  public CkTokenInfo getTokenInfo() throws PKCS11Exception {
    return slot.getModule().getPKCS11().C_GetTokenInfo(slotID);
  }

  /**
   * Get the list of mechanisms that this token supports. An application can
   * use this method to determine, if this token supports the required
   * mechanism.
   *
   * @return An array of Mechanism objects. Each describes a mechanism that
   *         this token can perform. This array may be empty but not null.
   */
  public long[] getMechanismList() {
    return mechCodes.clone();
  }

  /**
   * Get more information about one supported mechanism. The application can
   * find out, e.g. if an algorithm supports the certain key length.
   *
   * @param mechanism
   *        A mechanism that is supported by this token.
   * @return An information object about the concerned mechanism.
   */
  public CkMechanismInfo getMechanismInfo(long mechanism) {
    return mechCodeInfoMap.get(mechanism);
  }

  /**
   * Open a new session to perform operations on this token. Notice that all
   * sessions within one application (system process) have the same login
   * state.
   *
   * @param rwSession
   *        Must be either SessionReadWriteBehavior.RO_SESSION for read-only
   *        sessions or SessionReadWriteBehavior.RW_SESSION for read-write
   *        sessions.
   * @param auth
   *        Authentication of the PKCS#11 session. May be null.
   * @return The newly opened session.
   * @exception PKCS11Exception
   *            If the session could not be opened.
   */
  public Session openSession(boolean rwSession, SessionAuth auth)
      throws PKCS11Exception {
    long flags = rwSession
        ? CKF_SERIAL_SESSION | CKF_RW_SESSION : CKF_SERIAL_SESSION;
    long sessionHandle = rawOpenSession(flags, null);
    Session session = new Session(this, sessionHandle, flags);
    session.setAuth(auth);
    return session;
  }

  synchronized long rawOpenSession(long flags, Long oldHandle)
      throws PKCS11Exception {
    long sessionHandle = slot.getModule().getPKCS11().C_OpenSession(
        slotID, flags, oldHandle);

    LOG.info(
        "C_OpenSession: slotID={}, flags=0x{}, sessionHandle={}",
        slotID, Functions.toFullHex(flags), sessionHandle);
    return sessionHandle;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  @Override
  public String toString() {
    return "Token in Slot: " + "Slot ID: 0x" + Long.toHexString(slotID) +
        "\nModule: " + slot.getModule();
  }

}
