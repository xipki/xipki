// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Category;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.Slot;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.type.CkSlotInfo;
import org.xipki.pkcs11.wrapper.type.CkTokenInfo;
import org.xipki.util.codec.Args;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.misc.LogUtil;
import org.xipki.util.io.IoUtil;
import org.xipki.util.password.PasswordResolverException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * PKCS#11 module.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class P11Module {

  private static final Logger LOG = LoggerFactory.getLogger(P11Module.class);

  private final P11ModuleConf conf;

  private final Map<P11SlotId, P11Slot> slots = new HashMap<>();

  private final List<P11SlotId> slotIds = new ArrayList<>();

  private final PKCS11Module module;

  public P11Module(PKCS11Module module, P11ModuleConf moduleConf)
      throws TokenException {
    this.conf = Args.notNull(moduleConf, "moduleConf");

    if (CollectionUtil.isNotEmpty(moduleConf.getNativeLibraryProperties())) {
      throw new TokenException(
          "nativeLibraries[i].properties is present but not allowed.");
    }

    this.module = Args.notNull(module, "module");

    Slot[] slotList;
    try {
      slotList = module.getSlotList(false);
    } catch (Throwable th) {
      final String msg = "could not getSlotList of module " +
          moduleConf.getName();
      LogUtil.error(LOG, th, msg);
      throw new TokenException(msg);
    }

    final int size = (slotList == null) ? 0 : slotList.length;
    if (size == 0) {
      throw new TokenException("no slot could be found");
    }

    for (int i = 0; i < size; i++) {
      Slot slot = slotList[i];
      CkSlotInfo slotInfo;
      try {
        slotInfo = slot.getSlotInfo();
      } catch (TokenException ex) {
        LOG.error("ignore slot[{}] (id={}) with error", i, slot.getSlotID());
        slotList[i] = null;
        continue;
      }

      if (!slotInfo.isTokenPresent()) {
        slotList[i] = null;
        LOG.info("ignore slot[{}] (id={}) without token", i, slot.getSlotID());
      }
    }

    StringBuilder msg = new StringBuilder();

    List<P11Slot> slots = new ArrayList<>(slotList.length);
    for (int i = 0; i < slotList.length; i++) {
      Slot slot = slotList[i];
      if (slot == null) {
        continue;
      }

      P11SlotId slotId = new P11SlotId(i, slot.getSlotID());
      if (!moduleConf.isSlotIncluded(slotId)) {
        LOG.info("skipped slot {}", slotId);
        continue;
      }

      CkTokenInfo ti = slot.getToken().getTokenInfo();
      if (!ti.isTokenInitialized()) {
        LOG.info("slot {} not initialized, skipped it.", slotId);
        continue;
      }

      if (LOG.isDebugEnabled()) {
        msg.append("--------------------Slot ").append(i)
            .append("--------------------\n")
            .append("id: ").append(slot.getSlotID()).append("\n");
        try {
          msg.append(slot.getSlotInfo()).append("\n");
        } catch (TokenException ex) {
          msg.append("error: ").append(ex.getMessage());
        }
      }

      List<String> pwd;
      try {
        pwd = moduleConf.getPasswordRetriever().getPassword(slotId);
      } catch (PasswordResolverException ex) {
        throw new TokenException(
            "PasswordResolverException: " + ex.getMessage(), ex);
      }

      long userType = Optional.ofNullable(module.nameToCode(
          Category.CKU, getConf().getUserType())).orElseThrow(() ->
            new TokenException("Unknown user type " + getConf().getUserType()));

      PKCS11Token token = new PKCS11Token(slot.getToken(),
          moduleConf.isReadOnly(), userType, moduleConf.getUserName(),
          pwd, moduleConf.getNumSessions());

      token.setMaxMessageSize(moduleConf.getMaxMessageSize());
      if (moduleConf.getNewSessionTimeout() != null) {
        token.setTimeOutWaitNewSession(moduleConf.getNewSessionTimeout());
      }

      P11Slot p11Slot = new P11Slot(moduleConf.getName(), slotId, token,
          moduleConf.getP11MechanismFilter());

      slots.add(p11Slot);
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("{}", msg);
    }

    this.slots.clear();
    this.slotIds.clear();
    for (P11Slot slot : slots) {
      this.slots.put(slot.getSlotId(), slot);
      this.slotIds.add(slot.getSlotId());
    }
  }

  public String getName() {
    return conf.getName();
  }

  public P11ModuleConf getConf() {
    return conf;
  }

  /**
   * Returns slot for the given {@code slotId}.
   *
   * @param slotId
   *          slot identifier. Must not be {@code null}.
   * @return the slot
   * @throws TokenException
   *         if PKCS#11 token error occurs
   */
  public P11Slot getSlot(P11SlotId slotId) throws TokenException {
    return Optional.ofNullable(slots.get(Args.notNull(slotId, "slotId")))
        .orElseThrow(() -> new TokenException("unknown slot " + slotId));
  }

  public List<P11SlotId> getSlotIds() {
    return slotIds;
  }

  public P11SlotId getSlotIdForIndex(int index) throws TokenException {
    for (P11SlotId id : slotIds) {
      if (id.getIndex() == index) {
        return id;
      }
    }
    throw new TokenException("could not find slot with index " + index);
  }

  public P11SlotId getSlotIdForId(long id) throws TokenException {
    for (P11SlotId slotId : slotIds) {
      if (slotId.getId() == id) {
        return slotId;
      }
    }
    throw new TokenException("could not find slot with id " + id);
  }

  public static P11Module getInstance(P11ModuleConf moduleConf)
      throws TokenException {
    String userTypeStr = Args.notNull(moduleConf, "moduleConf").getUserType();
    Long userType = PKCS11T.ckuNameToCode(userTypeStr);

    if (userType != null) {
      if (userType == PKCS11T.CKU_SO) {
        throw new TokenException(
            "CKU_SO is not allowed in P11Module, too dangerous.");
      }
    }

    String path = moduleConf.getNativeLibrary();
    path = IoUtil.expandFilepath(path, false);

    PKCS11Module module;
    try {
      module = PKCS11Module.getInstance(path);
    } catch (IOException ex) {
      final String msg = "could not load the PKCS#11 module " +
          moduleConf.getName() + ": " + path;
      LogUtil.error(LOG, ex, msg);
      throw new TokenException(msg, ex);
    }

    try {
      module.initialize();
    } catch (PKCS11Exception ex) {
      LogUtil.error(LOG, ex);
      close(moduleConf.getName(), module);
      throw ex;
    } catch (Throwable th) {
      LOG.error("unexpected Exception", th);
      close(moduleConf.getName(), module);
      throw new TokenException(th.getMessage());
    }

    return new P11Module(module, moduleConf);
  } // method getInstance

  public String getDescription() {
    return module.getDescription();
  }

  public void close() {
    for (P11SlotId slotId : getSlotIds()) {
      try {
        getSlot(slotId).close();
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "could not close PKCS#11 slot " + slotId);
      }
    }

    close(conf.getNativeLibrary(), module);
  }

  private static void close(String modulePath, PKCS11Module module) {
    if (module == null) {
      return;
    }

    LOG.info("close PKCS#11 module: {}", modulePath);
    try {
      module.close();
    } catch (Throwable th) {
      LogUtil.error(LOG, th, "could not close module " + modulePath);
    }
  }

}
