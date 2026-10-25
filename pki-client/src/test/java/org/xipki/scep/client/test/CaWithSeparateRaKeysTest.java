// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client.test;

import org.xipki.pkix.scep.transaction.CaCapability;

/**
 * Test with RA which has separate keys for signature and encryption.
 *
 * @author Lijun Liao (xipki)
 */

public class CaWithSeparateRaKeysTest extends AbstractCaTest {

  @Override
  protected CaCapability[] getExcludedCaCaps() {
    return null;
  }

  @Override
  protected boolean isWithSeparateRaKeys() {
    return true;
  }

}
