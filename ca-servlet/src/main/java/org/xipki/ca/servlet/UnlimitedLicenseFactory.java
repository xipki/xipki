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

package org.xipki.ca.servlet;

import org.xipki.license.api.CmLicense;
import org.xipki.license.api.LicenseFactory;
import org.xipki.license.api.OcspLicense;

/**
 * Unlimited license factory.
 * @author Lijun Liao
 *
 */
public class UnlimitedLicenseFactory implements LicenseFactory {

  private class UnlimitedCmLicense implements CmLicense {

    @Override
    public boolean isValid() {
      return true;
    }

    @Override
    public boolean grantAllCAs() {
      return true;
    }

    @Override
    public boolean grant(String caSubject) {
      return true;
    }

    @Override
    public void regulateSpeed() {
    }

    @Override
    public long getMaxNumberOfCerts() {
      return -1;
    }

  } // class UnlimitedLicense

  public UnlimitedLicenseFactory() {
  }

  @Override
  public CmLicense createCmLicense() {
    return new UnlimitedCmLicense();
  }

  @Override
  public OcspLicense createOcspLicense() {
    throw new UnsupportedOperationException("createOcspLicense unsupported.");
  }

  @Override
  public void close() {
  }

}
