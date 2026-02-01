// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package test.pkcs11.wrapper.basics;

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.xipki.pkcs11.wrapper.PKCS11Module;
import org.xipki.pkcs11.wrapper.Slot;
import org.xipki.pkcs11.wrapper.Token;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.pkcs11.wrapper.type.CkInfo;
import org.xipki.pkcs11.wrapper.type.CkMechanismInfo;
import org.xipki.pkcs11.wrapper.type.CkSlotInfo;
import org.xipki.pkcs11.wrapper.type.CkTokenInfo;
import test.pkcs11.wrapper.TestBase;
import test.pkcs11.wrapper.TestHSMs;

import java.util.List;

import static org.xipki.pkcs11.wrapper.PKCS11T.ckmCodeToName;

/**
 * This demo program lists information about a library, the available slots, the
 * available tokens and the objects on them.
 *
 * @author Lijun Liao (xipki)
 */
@RunWith(Enclosed.class)
public class GetInfoTest {

  public static class Cloudhsm extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.cloudhsm();
    }
  }

  public static class Luna extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.luna();
    }
  }

  public static class Ncipher extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.ncipher();
    }
  }

  public static class Sansec extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.sansec();
    }
  }

  public static class Tass extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.tass();
    }
  }

  public static class Softhsm extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.softhsm();
    }
  }

  public static class Utimaco extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.utimaco();
    }
  }

  public static class Xihsm extends Base {
    @Override
    protected TestHSMs.TestHSM getHSM() {
      return TestHSMs.xihsm();
    }
  }

  private static abstract class Base extends TestBase {

    @Test
    public void execTest() throws TokenException {
      PKCS11Module pkcs11Module = getModule();
      CkInfo moduleInfo = pkcs11Module.getInfo();
      LOG.info("##################################################");
      LOG.info("{}", moduleInfo);
      LOG.info("##################################################");
      LOG.info("getting list of all slots");
      Slot[] slots = pkcs11Module.getSlotList(false);

      for (Slot slot : slots) {
        LOG.info("___________________________________________________");
        CkSlotInfo slotInfo = slot.getSlotInfo();
        LOG.info("Slot with ID: {}", slot.getSlotID());
        LOG.info("--------------------------------------------------");
        LOG.info("{}", slotInfo);
      }

      LOG.info("##################################################");
      LOG.info("getting list of all tokens");
      Slot[] slotsWithToken = pkcs11Module.getSlotList(true);
      Token[] tokens = new Token[slotsWithToken.length];

      for (int i = 0; i < slotsWithToken.length; i++) {
        LOG.info("___________________________________________________");
        tokens[i] = slotsWithToken[i].getToken();
        CkTokenInfo tokenInfo = tokens[i].getTokenInfo();
        LOG.info("Token in slot with ID: {}", tokens[i].getSlot().getSlotID());
        LOG.info("--------------------------------------------------");
        LOG.info("{}", tokenInfo);

        LOG.info("supported Mechanisms:");
        List<Long> supportedMechanisms = getMechanismList(tokens[i]);
        for (long supportedMechanism : supportedMechanisms) {
          LOG.info("--------------------------------------------------");
          CkMechanismInfo mechanismInfo =
              tokens[i].getMechanismInfo(supportedMechanism);
          LOG.info("--------------------------------------------------");
          LOG.info("Mechanism: {}\n{}",
              ckmCodeToName(supportedMechanism), mechanismInfo);
        }
        LOG.info("___________________________________________________");
      }
    }
  }

}
