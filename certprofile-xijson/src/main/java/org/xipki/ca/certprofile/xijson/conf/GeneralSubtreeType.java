/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

import com.alibaba.fastjson.annotation.JSONField;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class GeneralSubtreeType extends ValidatableConf {

  public static class Base extends ValidatableConf {
    @JSONField(ordinal = 1)
    private String rfc822Name;

    @JSONField(ordinal = 2)
    private String dnsName;

    @JSONField(ordinal = 3)
    private String directoryName;

    @JSONField(ordinal = 4)
    private String uri;

    @JSONField(ordinal = 5)
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
        throw new InvalidConfException("exact one of directoryName, dnsName, ipAddress, rfc822Name,"
            + " and uri must be set");
      }
    }
  }

  @JSONField(ordinal = 1)
  private Base base;

  @JSONField(ordinal = 2)
  private Integer minimum;

  @JSONField(ordinal = 3)
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
