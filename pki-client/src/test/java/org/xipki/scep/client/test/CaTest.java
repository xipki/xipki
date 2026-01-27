// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client.test;

import org.xipki.security.scep.transaction.CaCapability;

/**
 * Test the basic CA operation.
 *
 * @author Lijun Liao (xipki)
 */

public class CaTest extends AbstractCaTest {

  @Override
  protected CaCapability[] getExcludedCaCaps() {
    return null;
  }

}
