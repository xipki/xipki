// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

/**
 * Configuration of GeneralSubtree.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class GeneralSubtreeType extends ValidableConf {

  public static class Base extends ValidableConf {
    private String rfc822Name;

    private String dnsName;

    private String directoryName;

    private String uri;

    private String ipAddress;

    public String getRfc822Name() {
      return rfc822Name;
    }

    public void setRfc822Name(String rfc822Name) {
      this.rfc822Name = rfc822Name;
    }

    public String getDnsName() {
      return dnsName;
    }

    public void setDnsName(String dnsName) {
      this.dnsName = dnsName;
    }

    public String getDirectoryName() {
      return directoryName;
    }

    public void setDirectoryName(String directoryName) {
      this.directoryName = directoryName;
    }

    public String getUri() {
      return uri;
    }

    public void setUri(String uri) {
      this.uri = uri;
    }

    public String getIpAddress() {
      return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
      this.ipAddress = ipAddress;
    }

    @Override
    public void validate() throws InvalidConfException {
      int occurs = 0;
      if (directoryName != null) {
        occurs++;
      }

      if (dnsName != null) {
        occurs++;
      }

      if (ipAddress != null) {
        occurs++;
      }

      if (rfc822Name != null) {
        occurs++;
      }

      if (uri != null) {
        occurs++;
      }

      if (occurs != 1) {
        throw new InvalidConfException(
            "exact one of directoryName, dnsName, ipAddress, rfc822Name, and uri must be set");
      }
    } // method validate
  } // class Base

  private Base base;

  private Integer minimum;

  private Integer maximum;

  public Integer getMinimum() {
    return minimum;
  }

  public void setMinimum(Integer minimum) {
    this.minimum = minimum;
  }

  public Integer getMaximum() {
    return maximum;
  }

  public void setMaximum(Integer maximum) {
    this.maximum = maximum;
  }

  public Base getBase() {
    return base;
  }

  public void setBase(Base base) {
    this.base = base;
  }

  @Override
  public void validate() throws InvalidConfException {
    notNull(base, "base");
    validate(base);
  }

}
