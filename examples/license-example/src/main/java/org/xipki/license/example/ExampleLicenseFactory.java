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

package org.xipki.license.example;

import org.xipki.license.api.CmLicense;
import org.xipki.license.api.LicenseFactory;
import org.xipki.license.api.OcspLicense;

/**
 * Example license factory.
 * @author Lijun Liao
 *
 */
public class ExampleLicenseFactory implements LicenseFactory {

  private static class ExampleCmLicense implements CmLicense {

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

  } // class ExampleCmLicense

  private static class ExampleOcspLicense implements OcspLicense {

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

  } // class ExampleOcspLicense

  public ExampleLicenseFactory() {
  }

  @Override
  public CmLicense createCmLicense() {
    return new ExampleCmLicense();
  }

  @Override
  public OcspLicense createOcspLicense() {
    return new ExampleOcspLicense();
  }

  @Override
  public void close() {
  }

}
