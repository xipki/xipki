// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.license.example;

import org.xipki.license.api.CmLicense;
import org.xipki.license.api.LicenseFactory;
import org.xipki.license.api.OcspLicense;

/**
 * Example license factory.
 * @author Lijun Liao (xipki)
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
