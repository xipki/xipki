// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client.test;

import org.xipki.security.scep.transaction.CaCapability;

/**
 * Test CA with only HTTP GET (no POST) support.
 *
 * @author Lijun Liao (xipki)
 */

public class HttpGetOnlyCaTest extends AbstractCaTest {

  @Override
  protected CaCapability[] getExcludedCaCaps() {
    return new CaCapability[]{CaCapability.POSTPKIOperation,
        CaCapability.SCEPStandard};
  }

}
