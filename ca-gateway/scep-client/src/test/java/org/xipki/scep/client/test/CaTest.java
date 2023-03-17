// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client.test;

import org.xipki.scep.transaction.CaCapability;

/**
 * Test the basic CA operation.
 *
 * @author Lijun Liao
 */

public class CaTest extends AbstractCaTest {

  @Override
  protected boolean isWithRa() {
    return true;
  }

  @Override
  protected CaCapability[] getExcludedCaCaps() {
    return null;
  }

}
