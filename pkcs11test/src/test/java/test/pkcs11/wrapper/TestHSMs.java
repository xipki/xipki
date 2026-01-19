// Copyright (c) 2022 xipki. All rights reserved.
// License Apache License 2.0
package test.pkcs11.wrapper;

import org.junit.Assume;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.PKCS11Token;
import org.xipki.pkcs11.wrapper.Slot;
import org.xipki.pkcs11.wrapper.Token;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Lijun Liao (xipki)
 */
public class TestHSMs {

  private static final boolean defaultEnabled = true;

  private static final String cloudhsm = "cloudhsm";

  private static final String ncipher = "ncipher";

  private static final String luna = "luna";

  private static final String sansec = "sansec";

  private static final String softhsm = "softhsm";

  private static final String tass = "tass";

  private static final String utimaco = "utimaco";

  private static final String xihsm = "xihsm";
  private static final Logger log = LoggerFactory.getLogger(TestHSMs.class);

  private static String speedHsmName;

  private static int speedThreads;

  private static String speedDuration;

  private static final Map<String, Boolean> enableds;
  private static final Map<String, TestHSM> hsms = new HashMap<>();

  private static RuntimeException initException;

  static {
    enableds = Map.of(
        cloudhsm,       defaultEnabled,
        ncipher,        defaultEnabled,
        luna,           defaultEnabled,
        sansec,         defaultEnabled,
        softhsm,        defaultEnabled,
        tass,           defaultEnabled,
        utimaco,        defaultEnabled,
        xihsm,          defaultEnabled
    );

    try (InputStream is = TestHSMs.class.getClassLoader()
        .getResourceAsStream("pkcs11.json")) {
      if (is == null) {
        throw new RuntimeException("found no pkcs11.json");
      }

      JsonMap map = JsonParser.parseMap(is, true);
      JsonMap speedMap = map.getNnMap("speed");
      Integer ivalue = speedMap.getInt("threads");
      speedThreads = (ivalue == null) ? 2 : ivalue;

      String str = speedMap.getString("duration");
      speedDuration = (str == null) ? "3s" : str;

      speedHsmName = speedMap.getNnString("module");

      JsonList moduleConfs = map.getList("modules");
      Map<String, HsmConf> hsmConfMap = new HashMap<>();
      for (JsonMap moduleConf : moduleConfs.toMapList()) {
        String name = moduleConf.getNnString("name");
        Boolean b = enableds.get(name);
        if (b == null || !b) {
          continue;
        }

        if (hsmConfMap.containsKey(name)) {
          throw new RuntimeException("duplicated HSM configuration " + name);
        }

        HsmConf hsmConf = new HsmConf();
        hsmConf.path   = moduleConf.getNnString("path");
        hsmConf.pin    = moduleConf.getNnString("pin");
        hsmConf.soPin  = moduleConf.getNnString("soPin");
        hsmConf.numSessions = moduleConf.getInt("numSessions");
        hsmConf.slotIndex   = moduleConf.getInt("slotIndex");
        hsmConfMap.put(name, hsmConf);
      }

      Map<String, PKCS11Module> modules = new HashMap<>();
      try {
        for (Map.Entry<String, HsmConf> kv : hsmConfMap.entrySet()) {
          String name = kv.getKey();
          HsmConf v = kv.getValue();
          PKCS11Module module = PKCS11Module.getInstance(v.path);
          module.initialize();
          modules.put(name, module);

          PKCS11Token token = new PKCS11Token(
              selectToken(module, v.slotIndex), false,
              v.pin.getBytes(StandardCharsets.UTF_8), v.numSessions);
          hsms.put(name, new TestHSM(token, module, v.soPin));
        }
      } finally {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
          for (Map.Entry<String, PKCS11Module> kv : modules.entrySet()) {
            String name = kv.getKey();
            log.info("finalizing HSM module {}", name);
            try {
              kv.getValue().close();
            } catch (PKCS11Exception ex) {
              log.error("error closing HSM module {}", name, ex);
            }
          }
        }));
      }
    } catch (IOException | CodecException | TokenException e) {
      initException = new RuntimeException(e);
    } catch (RuntimeException e) {
      initException = e;
    }
  }

  public static int getSpeedThreads() {
    return speedThreads;
  }

  public static String getSpeedDuration() {
    return speedDuration;
  }

  public static TestHSM cloudhsm() {
    return getHsm(cloudhsm);
  }

  public static TestHSM luna() {
    return getHsm(luna);
  }

  public static TestHSM ncipher() {
    return getHsm(ncipher);
  }

  public static TestHSM sansec() {
    return getHsm(sansec);
  }

  public static TestHSM softhsm() {
    return getHsm(softhsm);
  }

  public static TestHSM tass() {
    return getHsm(tass);
  }

  public static TestHSM xihsm() {
    return getHsm(xihsm);
  }

  public static TestHSM utimaco() {
    return getHsm(utimaco);
  }

  public static TestHSM getHsmForSpeed() {
    return getHsm(speedHsmName);
  }

  private static TestHSM getHsm(String name) {
    if (initException != null) {
      throw initException;
    }

    TestHSM hsm = hsms.get(name);
    Assume.assumeTrue(name + " is not enabled", hsm != null);
    return hsm;
  }

  /**
   * Lists all available tokens of the given module and lets the user select
   * one, if there is more than one available. Supports token preselection.
   *
   * @param pkcs11Module
   *        The PKCS#11 module to use.
   * @param slotIndex
   *        The slot index, beginning with 0.
   * @return The selected token or null, if no token is available or the user
   *         canceled the action.
   * @exception PKCS11Exception
   *            If listing the tokens failed.
   */
  private static Token selectToken(PKCS11Module pkcs11Module, Integer slotIndex)
      throws TokenException {
    if (pkcs11Module == null) {
      throw new NullPointerException("Argument pkcs11Module must not be null.");
    }

    Slot[] slots = pkcs11Module.getSlotList(true);
    if (slots == null || slots.length == 0) {
      throw new IllegalStateException("no slot is available.");
    } else if (slotIndex != null) {
      if (slotIndex >= slots.length) {
        throw new IllegalArgumentException("slotIndex outOfRange.");
      } else {
        Token token = slots[slotIndex].getToken();
        if (!token.getTokenInfo().hasFlagBit(
            PKCS11T.CKF_TOKEN_INITIALIZED)) {
          throw new IllegalArgumentException("token is not initialized");
        } else {
          return token;
        }
      }
    } else {
      // return the first initialized token
      for (Slot slot : slots) {
        if (slot.getToken().getTokenInfo().hasFlagBit(
            PKCS11T.CKF_TOKEN_INITIALIZED)) {
          return slot.getToken();
        }
      }

      throw new IllegalArgumentException("found no initialized token");
    }
  }

  public static class TestHSM {

    private final PKCS11Token token;

    private final byte[] soPin;

    private final PKCS11Module module;

    private TestHSM(PKCS11Token token, PKCS11Module module, String soPin) {
      this.token = token;
      this.module = module;
      this.soPin = soPin == null ? null
          : soPin.getBytes(StandardCharsets.UTF_8);
    }

    public PKCS11Token getToken() {
      return token;
    }

    public PKCS11Module getModule() {
      return module;
    }

    public byte[] getSoPin() {
      return soPin;
    }

  }

  private static class HsmConf {
    private String path;
    private String pin;
    private String soPin;
    private Integer numSessions;
    private Integer slotIndex;
  }

}
