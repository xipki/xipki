// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.scep.client.test;

import org.xipki.scep.transaction.CaCapability;

/**
 * Test CA without CMS signer certificate.
 *
 * @author Lijun Liao
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
