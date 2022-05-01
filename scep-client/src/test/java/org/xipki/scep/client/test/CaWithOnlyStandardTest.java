/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.scep.client.test;

import org.xipki.scep.transaction.CaCapability;

/**
 * Test CA with only the CACapability SCEPStandard.
 *
 * @author Lijun Liao
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
