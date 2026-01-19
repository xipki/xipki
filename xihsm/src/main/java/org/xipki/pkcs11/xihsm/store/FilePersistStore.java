// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.store;

import org.bouncycastle.util.BigIntegers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.xihsm.Backend;
import org.xipki.pkcs11.xihsm.LoginState;
import org.xipki.pkcs11.xihsm.StoreSlotInfo;
import org.xipki.pkcs11.xihsm.XiHsmVendor;
import org.xipki.pkcs11.xihsm.attr.XiTemplate;
import org.xipki.pkcs11.xihsm.mgr.ModuleInitConf;
import org.xipki.pkcs11.xihsm.mgr.SlotUsers;
import org.xipki.pkcs11.xihsm.mgr.StoreMgrUtil;
import org.xipki.pkcs11.xihsm.mgr.TenantInfo;
import org.xipki.pkcs11.xihsm.objects.XiP11Storage;
import org.xipki.pkcs11.xihsm.util.HsmException;
import org.xipki.pkcs11.xihsm.util.ObjectInitMethod;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.io.IoUtil;
import org.xipki.util.misc.LruCache;
import org.xipki.util.misc.StringUtil;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_ACTION_PROHIBITED;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_GENERAL_ERROR;
import static org.xipki.pkcs11.wrapper.PKCS11T.CKR_OBJECT_HANDLE_INVALID;

/**
 * @author Lijun Liao (xipki)
 */
public class FilePersistStore implements PersistStore {

  private static final Logger LOG =
      LoggerFactory.getLogger(FilePersistStore.class);

  private static final int MAX_NUM_CHARS_HANDLE =
      2 * BigIntegers.asUnsignedByteArray(
          (BigInteger.valueOf(Backend.MAX_TOKEN_HANDLE))).length;

  private final long[] slotIds;

  private final StoreSlotInfo[] slotInfos;

  private final HashMap<Long, FileSlot> idSlotMap = new HashMap<>();

  private final File basedir;

  public FilePersistStore(
      XiHsmVendor vendor, String tenant, String parentBasedir)
      throws HsmException {
    Args.notNull(vendor, "vendor");

    if (StringUtil.isBlank(parentBasedir)) {
      parentBasedir = "~/.xihsm/store";
    }
    parentBasedir = IoUtil.expandFilepath(parentBasedir);

    if (StringUtil.isBlank(tenant)) {
      tenant = "default";
    }

    basedir = new File(parentBasedir, tenant);

    try {
      File infoFile = new File(basedir, "INFO");
      if (!infoFile.exists()) {
        ModuleInitConf initConf = StoreMgrUtil.newInstanceOfTestEnv(2);
        StoreMgrUtil.initFileModule(basedir, initConf);
        LOG.info("initialized HSM module for tenant {}", tenant);
      }

      // read configuration
      // read module conf
      TenantInfo tenantInfo = TenantInfo.decode(
          IoUtil.read(new File(basedir, "INFO")));

      // read slot conf
      List<FileSlot> slots = new ArrayList<>(2);
      int maxIndex = 0;

      File[] subDirs = basedir.listFiles();
      if (subDirs != null) {
        for (File subDir : subDirs) {
          if (!subDir.isDirectory()) {
            continue;
          }

          String[] tokens = subDir.getName().split("_");
          int slotIndex = Integer.parseInt(tokens[0]);
          long slotId = Long.parseLong(tokens[1]);

          if (slotIndex < 0 || slotIndex > 99) {
            LOG.warn("ignore slot with index {}", slotIndex);
            continue;
          }

          SlotUsers slotUsers = tenantInfo.getSlotUsers(slotId);
          if (slotUsers == null) {
            throw HsmException.newGeneralError(
                "no users are configured for slot id " + slotId);
          }

          FileSlot slot = new FileSlot(vendor, subDir,
              slotIndex, slotId, slotUsers);
          slots.add(slot);

          if (slotIndex > maxIndex) {
            maxIndex = slotIndex;
          }
        }
      }

      int numSlots = maxIndex + 1;
      this.slotIds = new long[numSlots];
      this.slotInfos = new StoreSlotInfo[numSlots];

      for (FileSlot slot : slots) {
        int i = slot.slotInfo.getSlotIndex();
        this.slotInfos[i] = slot.slotInfo;
        this.slotIds[i] = slot.slotInfo.getSlotId();
        this.idSlotMap.put(this.slotIds[i], slot);
      }

      for (int i = 0; i < numSlots; i++) {
        if (slotInfos[i] == null) {
          throw HsmException.newGeneralError(
              "no slot is configured for index " + i);
        }
      }
    } catch (IOException ex) {
      throw HsmException.newGeneralError(
          "error initializing file-based store", ex);
    }
  }

  private FileSlot slot(long slotId) throws HsmException {
    return Optional.ofNullable(idSlotMap.get(slotId)).orElseThrow(() ->
        new HsmException(PKCS11T.CKR_SLOT_ID_INVALID,
            "invalid slot id " + slotId));
  }

  public File getBasedir() {
    return basedir;
  }

  @Override
  public void addObject(long slotId, XiP11Storage object) throws HsmException {
    slot(slotId).addObject(object);
  }

  @Override
  public void findObjects(List<Long> res, long slotId,
                          LoginState loginState, XiTemplate criteria)
      throws HsmException {
    slot(slotId).findObjects(res, loginState, criteria);
  }

  @Override
  public XiP11Storage getObject(
      long slotId, long hObject, LoginState loginState) throws HsmException {
    return slot(slotId).getFileObject(hObject, loginState).obj;
  }

  @Override
  public void updateObject(
      long slotId, long hObject, LoginState loginState, XiTemplate attrs)
      throws HsmException {
    slot(slotId).updateObject(hObject, loginState, attrs);
  }

  @Override
  public void destroyObject(long slotId, long hObject, LoginState loginState)
      throws HsmException {
    slot(slotId).destroyObject(hObject, loginState);
  }

  @Override
  public long nextObjectHandle(long slotId) throws HsmException {
    return slot(slotId).nextObjectHandle();
  }

  @Override
  public long[] nextKeyPairHandles(long slotId) throws HsmException {
    return slot(slotId).nextObjectHandles(2);
  }

  @Override
  public StoreSlotInfo[] getSlotInfos() {
    return slotInfos.clone();
  }

  @Override
  public long[] getSlotIds() {
    return slotIds.clone();
  }

  @Override
  public void close() {
  }

  private static class FileSlot extends PersistSlot {

    private final LruCache<Long, FileP11Storage> cache = new LruCache<>(1024);

    private final AtomicLong nextHandle;

    private final File slotDir;

    FileSlot(XiHsmVendor vendor, File slotDir,
             int slotIndex, long slotId, SlotUsers users) {
      super(vendor,
          new StoreSlotInfo(vendor, slotIndex, slotId,
                "sn-1234", "file-slot-" + slotId, users));
      this.slotDir = Args.notNull(slotDir, "slotDir");

      String[] fileNames = this.slotDir.list();
      long maxHandle = 0;
      if (fileNames != null) {
        for (String fileName : fileNames) {
          if (fileName.length() != MAX_NUM_CHARS_HANDLE) {
            continue;
          }

          try {
            long handle = Integer.parseInt(fileName, 16);
            if (maxHandle < handle) {
              maxHandle = handle;
            }
          } catch (RuntimeException e) {
          }
        }
      }

      this.nextHandle = new AtomicLong(maxHandle + 1);
    }

    private static String toFileName(long handle) {
      if (handle < 0 || handle >= 0xFFFFFF) {
        throw new IllegalArgumentException("invalid handle " + handle);
      }

      String str = Long.toString(handle, 16);
      if (str.length() < MAX_NUM_CHARS_HANDLE) {
        str = "0".repeat(MAX_NUM_CHARS_HANDLE - str.length()) + str;
      }
      return str;
    }

    public void addObject(XiP11Storage obj) throws HsmException {
      long handle = obj.getHandle();
      String fileName = toFileName(handle);
      File objFile = new File(slotDir, fileName);
      if (objFile.exists() || objFile.exists()) {
        throw new HsmException(CKR_GENERAL_ERROR, "handle exists: " + handle);
      }

      saveObject(objFile, obj.getAllAttributes());
      LOG.info("added object {} to slot {}", handle, slotInfo.getSlotId());
    }

    public void destroyObject(long hObject, LoginState loginState)
        throws HsmException {
      FileP11Storage obj = getFileObject(hObject, loginState);
      if (!obj.obj.isDestroyable()) {
        throw new HsmException(CKR_ACTION_PROHIBITED,
            "the object is not destroyable");
      }

      String fileName = toFileName(hObject);
      File infoFile = new File(slotDir, fileName + ".info");
      File valueFile = new File(slotDir, fileName);
      try {
        boolean deleted = false;
        if (infoFile.exists()) {
          infoFile.delete();
          deleted = true;
        }

        if (valueFile.exists()) {
          valueFile.delete();
          deleted = true;
        }

        if (!deleted) {
          throw new HsmException(CKR_OBJECT_HANDLE_INVALID,
              "handle does not exist: " + hObject);
        }
      } catch (RuntimeException e) {
        throw HsmException.newGeneralError(
            "error deleting files: " + e.getMessage(), e);
      }
    }

    private FileP11Storage getFileObject(long hObject, LoginState loginState)
        throws HsmException {
      String fileName = toFileName(hObject);
      File objFile = new File(slotDir, fileName);

      try {
        if (!(objFile.exists() && objFile.exists())) {
          throw new HsmException(CKR_OBJECT_HANDLE_INVALID,
              "found no object for hObject " + hObject);
        }

        FileP11Storage fileObj = cache.get(hObject);
        long modifiedAt = objFile.lastModified();

        if (fileObj != null) {
          if (modifiedAt > fileObj.lastModified) {
            cache.remove(hObject);
            fileObj = null;
          }
        }

        if (fileObj == null) {
          PersistObject po = PersistObject.decode(IoUtil.read(objFile));
          XiP11Storage obj = XiP11Storage.fromAttributes(
              vendor, hObject, po.toAttributes());
          fileObj = new FileP11Storage(obj, modifiedAt);
          cache.put(hObject, fileObj);
        }

        if (!fileObj.obj.isVisibleForCku(loginState)) {
          throw new HsmException(CKR_OBJECT_HANDLE_INVALID,
              "object is not visible");
        }

        return fileObj;
      } catch (IOException | RuntimeException | CodecException e) {
        throw HsmException.newGeneralError("error getting object", e);
      }
    }

    public void updateObject(long hObject, LoginState loginState,
                             XiTemplate newAttrs) throws HsmException {
      FileP11Storage fileObj = getFileObject(hObject, loginState);
      fileObj.obj.updateAttributes(loginState, ObjectInitMethod.UPDATE,
          newAttrs);

      String fileName = toFileName(hObject);
      File objFile = new File(slotDir, fileName);

      saveObject(objFile, fileObj.obj.getAllAttributes());
      cache.remove(hObject);
      LOG.info("updated object {} to slot {}", hObject, slotInfo.getSlotId());
    }

    private void saveObject(File objFile, XiTemplate attrs)
        throws HsmException {
      PersistObject po = from(attrs);
      try {
        IoUtil.save(objFile, po.getEncoded());
      } catch (CodecException | IOException e) {
        throw new HsmException(CKR_GENERAL_ERROR, e.getMessage(), e);
      }
    }

    public void findObjects(List<Long> result, LoginState loginState,
                            XiTemplate criteria)
        throws HsmException {
      File[] files = slotDir.listFiles((dir, name) -> {
        if (name.length() != 6) {
          return false;
        }

        for (int i = 0; i < 6; i++) {
          char c = name.charAt(i);
          if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
            continue;
          }

          return false;
        }

        return true;
      });

      if (files == null) {
        return;
      }

      for (File file : files) {
        try {
          byte[] encodedPo = IoUtil.read(file);
          PersistObject po = PersistObject.decode(encodedPo);
          if (!po.isVisibleForCku(vendor, loginState)) {
            continue;
          }

          if (po.match(criteria)) {
            long handle = Long.parseLong(file.getName(), 16);
            result.add(handle);
          }
        } catch (IOException | CodecException e) {
          throw HsmException.newGeneralError("error reading key " + file, e);
        }
      }
    }

    synchronized long[] nextObjectHandles(int num) throws HsmException {
      Args.range(num, "num", 1, 100);

      long[] ret = new long[num];
      int tries = 0;

      for (int i = 0; i < num; i++) {
        long cHandle = -1;
        while (tries < Backend.MAX_TOKEN_HANDLE) {
          tries++;
          long handle = nextHandle.getAndIncrement();
          if (nextHandle.get() > Backend.MAX_TOKEN_HANDLE) {
            LOG.warn("nextHandle reached end, reset it to 1");
            nextHandle.set(1L);
          }

          boolean handleFree = !new File(slotDir, toFileName(handle)).exists();

          if (handleFree) {
            cHandle = handle;
            break;
          }
        }

        if (cHandle == -1) {
          throw new HsmException(PKCS11T.CKR_GENERAL_ERROR,
              "no available handle");
        }

        ret[i] = cHandle;
      }

      return ret;
    }

    long nextObjectHandle() throws HsmException {
      return nextObjectHandles(1)[0];
    }

    private static final class FileP11Storage {
      private final XiP11Storage obj;
      private final long lastModified;

      public FileP11Storage(XiP11Storage obj, long lastModified) {
        this.obj = obj;
        this.lastModified = lastModified;
      }
    }
  }

}
