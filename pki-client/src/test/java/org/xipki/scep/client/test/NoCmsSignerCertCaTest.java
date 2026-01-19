// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client.test;

import org.xipki.security.scep.transaction.CaCapability;

/**
 * Test CA without CMS signer certificate.
 *
 * @author Lijun Liao (xipki)
 */

public class NoCmsSignerCertCaTest extends AbstractCaTest {

  @Override
  protected boolean sendSignerCert() {
    return false;
  }

  @Override
  protected CaCapability[] getExcludedCaCaps() {
    return null;
  }

}
