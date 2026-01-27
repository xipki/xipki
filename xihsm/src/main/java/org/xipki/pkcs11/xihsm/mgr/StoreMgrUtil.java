// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.mgr;

import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.crypt.HashAlgo;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.HsmUtil;
import org.xipki.util.io.IoUtil;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Lijun Liao (xipki)
 */
public class StoreMgrUtil {

  public static ModuleInitConf newInstanceOfTestEnv(int numSlots) {
    List<ModuleInitConf.Slot> slots = new ArrayList<>(numSlots);
    for (int i = 0; i < numSlots; i++) {
      slots.add(new ModuleInitConf.Slot(i + 100, "123456", "123456"));
    }
    return new ModuleInitConf(slots);
  }

  public static void initFileModule(File dir, ModuleInitConf conf)
      throws HsmException {
    TenantInfo info = generateTenantInfo(conf);

    try {
      IoUtil.save(new File(dir, "INFO"), info.encode());

      // Initialize slots
      int index = 0;
      for (ModuleInitConf.Slot slot : conf.getSlots()) {
        // slot-index '_' slot-id
        File slotDir = new File(dir, index + "_" + slot.getId());
        slotDir.mkdirs();
        index++;
      }
    } catch (IOException e) {
      throw HsmException.newGeneralError("error initializing module", e);
    }
  }

  private static TenantInfo generateTenantInfo(ModuleInitConf conf) {
    int numSlots = conf.getSlots().size();
    Map<Long, SlotUsers> slotUsersMap = new HashMap<>(numSlots);

    for (int i = 0; i < numSlots; i++) {
      ModuleInitConf.Slot slot = conf.getSlots().get(i);

      List<User> users = new ArrayList<>(2);

      Map<Long, String> userTypePinMap = Map.of(
          PKCS11T.CKU_SO,   slot.getSoPin(),
          PKCS11T.CKU_USER, slot.getUserPin());
      for (Map.Entry<Long, String> kv : userTypePinMap.entrySet()) {
        byte[] salt = HsmUtil.randomBytes(12);
        byte[] hash = HashAlgo.SHA256.hash(salt,
            kv.getValue().getBytes(StandardCharsets.UTF_8));
        users.add(new User(kv.getKey(), salt, hash));
      }

      slotUsersMap.put(slot.getId(), new SlotUsers(users));
    }

    return new TenantInfo(slotUsersMap);
  }

}
