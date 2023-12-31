// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client.test;

import org.xipki.scep.transaction.CaCapability;

/**
 * Test CA without RA.
 *
 * @author Lijun Liao (xipki)
 */

public class CaWithoutRaTest extends AbstractCaTest {

  @Override
  protected boolean isWithRa() {
    return false;
  }

  @Override
  protected CaCapability[] getExcludedCaCaps() {
    return null;
  }

}
