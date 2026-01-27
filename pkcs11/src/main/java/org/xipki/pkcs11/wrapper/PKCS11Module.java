// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkcs11.wrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.type.CkInfo;
import org.xipki.pkcs11.wrapper.type.CkMechanismInfo;
import org.xipki.pkcs11.wrapper.vendor.HsmVendor;
import org.xipki.pkcs11.wrapper.vendor.SpecialBehaviour;
import org.xipki.pkcs11.wrapper.vendor.VendorEnum;
import org.xipki.util.codec.Args;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_GENERAL_ERROR;

/**
 * <p>
 * Objects of this class represent a PKCS#11 module.
 *
 * @author Lijun Liao (xipki)
 */

public class PKCS11Module {

  private static final Logger LOG = LoggerFactory.getLogger(PKCS11Module.class);

  /**
   * Interface to the underlying PKCS#11 module.
   */
  private final LogPKCS11 pkcs11;

  private final String modulePath;

  private String description;

  private CkInfo moduleInfo;

  private Boolean ecdsaSignatureFixNeeded;

  private Boolean sm2SignatureFixNeeded;

  private HsmVendor hsmVendor;

  static {
    String version = null;
    try (BufferedReader reader = new BufferedReader(
        new InputStreamReader(Objects.requireNonNull(
            PKCS11Module.class.getResourceAsStream("version"))))) {
      version = reader.readLine();
    } catch (Exception ex) {
    }

    if (version == null) {
      version = "UNKNOWN";
    } else {
      version = version.trim();
    }

    LOG.info("ipkcs11wrapper {}", version);
  }

  /**
   * Create a new module that uses the given PKCS11 interface to interact with
   * the token.
   *
   * @param modulePath      The PKCS#11 module path.
   */
  protected PKCS11Module(String modulePath)
      throws IOException {
    Args.notNull(modulePath, "modulePath");
    this.pkcs11 = new LogPKCS11(modulePath, this);
    this.modulePath = Args.notNull(modulePath, "modulePath");
    LOG.info("PKCS11Module.<init>: pkcs11ModulePath={}", modulePath);
  }

  /**
   * Get an instance of this class by giving the name of the PKCS#11 module;
   *
   * @param modulePath
   *        The path of the module; e.g. "/path/to/libpkcs11.so".
   * @return An instance of Module that is connected to the given PKCS#11
   *         module.
   * @exception IOException
   *            If connecting to the named module fails.
   *
   */
  public static PKCS11Module getInstance(String modulePath) throws IOException {
    return new PKCS11Module(modulePath);
  }

  Boolean getEcdsaSignatureFixNeeded() {
    return ecdsaSignatureFixNeeded;
  }

  void setEcdsaSignatureFixNeeded(Boolean ecdsaSignatureFixNeeded) {
    this.ecdsaSignatureFixNeeded = ecdsaSignatureFixNeeded;
  }

  Boolean getSm2SignatureFixNeeded() {
    return sm2SignatureFixNeeded;
  }

  void setSm2SignatureFixNeeded(Boolean sm2SignatureFixNeeded) {
    this.sm2SignatureFixNeeded = sm2SignatureFixNeeded;
  }

  /**
   * Gets information about the module; i.e. the PKCS#11 module behind.
   *
   * @return An object holding information about the module.
   */
  public CkInfo getInfo() throws TokenException {
    if (moduleInfo == null) {
      throw new TokenException("moduleInfo not available");
    }
    return moduleInfo;
  }

  /**
   * Initializes the module. The application must call this method before
   * calling any other method of the module.
   *
   * @exception PKCS11Exception
   *              If initialization fails.
   */
  public void initialize() throws PKCS11Exception {
    moduleInfo = pkcs11.C_GetInfo();

    Slot[] slots = getSlotList(true);
    Set<Long> tokenMechanisms = null;
    if (slots != null && slots.length > 0) {
      tokenMechanisms = new HashSet<>();
      for(long ckm : slots[0].getToken().getMechanismList()) {
        tokenMechanisms.add(ckm);
      }
    }

    // Vendor code
    try {
      this.hsmVendor = HsmVendor.getInstance(modulePath, moduleInfo,
          tokenMechanisms);
    } catch (Exception e) {
      LOG.error("error initializing HsmVendor", e);
      throw new PKCS11Exception(CKR_GENERAL_ERROR);
    }

    this.description = "PKCS#11 wrapper" +
        "\n\tPath: " + modulePath +
        "\n\tCryptoki Version: " + moduleInfo.cryptokiVersion() +
        "\n\tManufacturerID: " + moduleInfo.manufacturerID() +
        "\n\tLibrary Description: " + moduleInfo.libraryDescription() +
        "\n\tLibrary Version: " + moduleInfo.libraryVersion() +
        "\n\tHSM vendor: " + hsmVendor.getName();

    LOG.info("PKCS#11 module\n{}", this.description);
  }

  public String getDescription() {
    return description;
  }

  /**
   * Finalizes this module. The application should call this method when it
   * finished using the module. Note that this method is different from the
   * <code>finalize</code> method, which is the reserved Java method called by
   * the garbage collector. This method calls the
   * <code>C_Finalize(Object)</code> method of the underlying PKCS11 module.
   *
   * @exception PKCS11Exception
   *            If finalization fails.
   *
   */
  public void close() throws PKCS11Exception {
    pkcs11.C_Finalize();
    pkcs11.close();
  }

  /**
   * Gets a list of slots that can accept tokens that are compatible with this
   * module; e.g. a list of PC/SC smart card readers. The parameter determines
   * if the method returns all compatible slots or only those in which there
   * is a compatible token present.
   *
   * @param tokenPresent
   *        Whether only slots with present token are returned.
   * @return An array of Slot objects, may be an empty array but not null.
   * @exception PKCS11Exception
   *            If error occurred.
   */
  public Slot[] getSlotList(boolean tokenPresent) throws PKCS11Exception {
    long[] slotIDs = pkcs11.C_GetSlotList(tokenPresent);

    Slot[] slots = new Slot[slotIDs.length];
    for (int i = 0; i < slots.length; i++) {
      slots[i] = new Slot(this, slotIDs[i]);
    }

    return slots;
  }

  /**
   * Gets the PKCS#11 module of the wrapper package behind this object.
   *
   * @return The PKCS#11 module behind this object.
   */
  public LogPKCS11 getPKCS11() {
    return pkcs11;
  }

  public CkMechanismInfo adaptMechanismFlags(long ckm, CkMechanismInfo mi) {
    if (hsmVendor != null) {
      long newFlags = hsmVendor.adaptMechanismFlags(ckm, mi.flags());
      return newFlags == mi.flags() ? mi
          : new CkMechanismInfo(mi.minKeySize(), mi.maxKeySize(), newFlags);
    } else {
      return mi;
    }
  }

  public int getMaxFrameSize() {
    return hsmVendor == null ? Integer.MAX_VALUE : hsmVendor.getMaxFrameSize();
  }

  public boolean supportsMultipart(long ckm, long flagBit) {
    return hsmVendor == null || hsmVendor.supportsMultipart(ckm, flagBit);
  }

  public VendorEnum getVendorEnum() {
    return hsmVendor == null ? VendorEnum.UNKNOWN : hsmVendor.getVendorEnum();
  }

  public HsmVendor getHsmVendor() {
    return hsmVendor;
  }

  public byte[] prepareGcmIv(SecureRandom rnd) {
    switch (getVendorEnum()) {
      case CLOUDHSM:
        return new byte[12];
      default:
        byte[] bytes = new byte[12];
        rnd.nextBytes(bytes);
        return bytes;
    }
  }

  public boolean hasSpecialBehaviour(SpecialBehaviour vendorBehavior) {
    return hsmVendor != null && hsmVendor.hasSpecialBehaviour(vendorBehavior);
  }

  public boolean hasAnySpecialBehaviour(SpecialBehaviour... vendorBehaviors) {
    return hsmVendor != null
        && hsmVendor.hasAnySpecialBehaviour(vendorBehaviors);
  }

  public boolean hasAllSpecialBehaviours(SpecialBehaviour... vendorBehaviors) {
    return hsmVendor != null
        && hsmVendor.hasAllSpecialBehaviours(vendorBehaviors);
  }

  public long genericToVendorCode(Category category, long genericCode) {
    return (hsmVendor != null)
        ? hsmVendor.genericToVendorCode(category, genericCode) : genericCode;
  }

  public long vendorToGenericCode(Category category, long vendorCode) {
    return (hsmVendor != null)
        ? hsmVendor.vendorToGenericCode(category, vendorCode) : vendorCode;
  }

  public String codeToName(Category category, long code) {
    if (hsmVendor != null) {
      return hsmVendor.codeToName(category, code);
    } else {
      return PKCS11T.codeToName(category, code);
    }
  }

  public Long nameToCode(Category category, String name) {
    if (hsmVendor != null) {
      return hsmVendor.nameToCode(category, name);
    } else {
      return PKCS11T.nameToCode(category, name);
    }
  }

  /**
   * Returns the string representation of this object.
   *
   * @return The string representation of object
   */
  @Override
  public String toString() {
    return (pkcs11 != null) ? pkcs11.toString() : "null";
  }

}
