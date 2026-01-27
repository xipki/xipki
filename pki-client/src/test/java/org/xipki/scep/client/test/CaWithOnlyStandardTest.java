// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client.test;

import org.xipki.security.scep.transaction.CaCapability;

/**
 * Test CA with only the CACapability SCEPStandard.
 *
 * @author Lijun Liao (xipki)
 */

public class CaWithOnlyStandardTest extends AbstractCaTest {

  @Override
  protected boolean isWithRa() {
    return false;
  }

  @Override
  protected CaCapability[] getExcludedCaCaps() {
    CaCapability[] rv = new CaCapability[CaCapability.values().length - 1];
    int i = 0;
    for (CaCapability c : CaCapability.values()) {
      if (c != CaCapability.SCEPStandard) {
        rv[i++] = c;
      }
    }
    return rv;
  }

}
