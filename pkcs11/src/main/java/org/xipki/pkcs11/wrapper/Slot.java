// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.xipki.pkcs11.wrapper.type.CkSlotInfo;
import org.xipki.util.codec.Args;

/**
 * Objects of this class represent slots that can accept tokens. The application
 * can get a token object if there is one present, by calling getToken.
 * This may look like this:
 * <pre><code>
 *   Token token = slot.getToken();
 *
 *   // to ensure that there is a token present in the slot
 *   if (token != null) {
 *     // ... work with the token
 *   }
 * </code></pre>
 *
 * @author Lijun Liao (xipki)
 */
public class Slot {

  /**
   * The module that created this slot object.
   */
  private final PKCS11Module module;

  /**
   * The identifier of the slot.
   */
  private final long slotID;

  private final Token token;

  /**
   * The constructor that takes a reference to the module and the slot ID.
   *
   * @param module
   *        The reference to the module of this slot.
   * @param slotID
   *        The identifier of the slot.
   */
  protected Slot(PKCS11Module module, long slotID) {
    this.module = Args.notNull(module, "module");
    this.slotID = slotID;
    this.token = new Token(this);
  }

  /**
   * Get the module that created this Slot object.
   *
   * @return The module of this slot.
   */
  public PKCS11Module getModule() {
    return module;
  }

  /**
   * Get the ID of this slot. This is the ID returned by the PKCS#11 module.
   *
   * @return The ID of this slot.
   */
  public long getSlotID() {
    return slotID;
  }

  /**
   * Get information about this slot object.
   *
   * @return An object that contains information about this slot.
   * @exception PKCS11Exception
   *            If reading the information fails.
   */
  public CkSlotInfo getSlotInfo() throws PKCS11Exception {
    return module.getPKCS11().C_GetSlotInfo(slotID);
  }

  /**
   * Get an object for handling the token that is currently present in this
   * slot, or null, if there is no token present.
   *
   * @return The object for accessing the token, non-null.
   * @exception PKCS11Exception
   *            If determining whether a token is present fails.
   */
  public Token getNullableToken() throws PKCS11Exception {
    return getSlotInfo().isTokenPresent() ? token : null;
  }

  /**
   * Get an object for handling the token that is currently present in this
   * slot.
   *
   * @return The object for accessing the token, non-null.
   */
  public Token getToken() {
    return token;
  }

  /**
   * Returns the string representation of this object.
   *
   * @return the string representation of this object
   */
  @Override
  public String toString() {
    return "Slot ID: 0x" + Long.toHexString(slotID) + "\nModule: " + module;
  }

}
