// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper.type;

import org.xipki.pkcs11.wrapper.Arch;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.EncodeList;
import org.xipki.pkcs11.wrapper.Functions;
import org.xipki.pkcs11.wrapper.PKCS11Module;

import java.util.concurrent.atomic.AtomicInteger;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_RW_SESSION;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKF_SERIAL_SESSION;

/**
 * An object of this class provides information about a session.
 * <pre>
 * typedef struct CK_SESSION_INFO {
 *   CK_SLOT_ID    slotID;
 *   CK_STATE      state;
 *   CK_FLAGS      flags;          // see below
 *   CK_ULONG      ulDeviceError;  // device-dependent error code
 * } CK_SESSION_INFO;
 * </pre>
 * @author Lijun Liao (xipki)
 */
public class CkSessionInfo extends AbstractInfo {

  /**
   * The identifier of the slot in which the token resides this session is
   * bound to.
   */
  private final long slotID;

  /**
   * The current session state.
   */
  private final long state;

  /**
   * A token specific error-code. The meaning of this value is not defined in
   * PKCS#11.
   */
  private final long deviceError;

  /**
   * The flags.
   */
  private final long flags;

  public CkSessionInfo(long slotID, long state, long flags, long deviceError) {
    this.slotID = slotID;
    this.state = state;
    this.flags = flags;
    this.deviceError = deviceError;
  }

  /**
   * Get the current state of this session.
   *
   * @return The current state of this session.
   */
  public long getState() {
    return state;
  }

  /**
   * Get the current device error-code of the token. Notice that this code is
   * device-specific. Its meaning is not defined in the PKCS#11 standard.
   *
   * @return The error-code of the device.
   */
  public long getDeviceError() {
    return deviceError;
  }

  /**
   * Check, if this is a read-write session.
   *
   * @return True, if this is a read-write session; false, if this is a
   *         read-only session.
   */
  public boolean isRwSession() {
    return (flags & CKF_RW_SESSION) != 0L;
  }

  @Override
  public String toString(PKCS11Module module, String indent) {
    return toString(indent, "CK_SESSION_INFO", null,
        "slotID", slotID, "state", codeToName(Category.CKS, state, module),
        "ulDeviceError", deviceError) + "\n"
        + Functions.toStringFlags(Category.CKF_SESSION, indent + "Flags: ",
            flags, CKF_RW_SESSION, CKF_SERIAL_SESSION);
  }

  @Override
  protected EncodeList getEncodeList() {
    return new EncodeList().v(slotID).v(state).v(flags).v(deviceError);
  }

  public static CkSessionInfo decode(Arch arch, byte[] encoded) {
    AtomicInteger off = new AtomicInteger();
    return new CkSessionInfo(
        readLong(arch, encoded, off), readLong(arch, encoded, off),
        readLong(arch, encoded, off), readLong(arch, encoded, off));
  }

}
