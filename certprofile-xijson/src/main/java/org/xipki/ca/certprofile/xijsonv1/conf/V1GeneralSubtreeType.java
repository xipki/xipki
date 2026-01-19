// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf;

import org.xipki.ca.certprofile.xijson.conf.GeneralSubtreeType;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.conf.InvalidConfException;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration of GeneralSubtree.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class V1GeneralSubtreeType {

  private static class Base {

    private String rfc822Name;

    private String dnsName;

    private String directoryName;

    private String uri;

    private String ipAddress;

    public void setRfc822Name(String rfc822Name) {
      this.rfc822Name = rfc822Name;
    }

    public void setDnsName(String dnsName) {
      this.dnsName = dnsName;
    }

    public void setDirectoryName(String directoryName) {
      this.directoryName = directoryName;
    }

    public void setUri(String uri) {
      this.uri = uri;
    }

    public void setIpAddress(String ipAddress) {
      this.ipAddress = ipAddress;
    }

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
        throw new InvalidConfException("exact one of directoryName, " +
            "dnsName, ipAddress, rfc822Name, and uri must be set");
      }
    } // method validate

    public static Base parse(JsonMap json) throws CodecException {
      Base ret = new Base();

      ret.setRfc822Name(json.getString("rfc822Name"));
      ret.setDnsName(json.getString("dnsName"));
      ret.setDirectoryName(json.getString("directoryName"));
      ret.setUri(json.getString("uri"));
      ret.setIpAddress(json.getString("ipAddress"));

      try {
        ret.validate();
      } catch (InvalidConfException e) {
        throw new CodecException(e);
      }
      return ret;
    }
  } // class Base

  private final Base base;

  private V1GeneralSubtreeType(Base base) {
    this.base = Args.notNull(base, "base");
  }

  public GeneralSubtreeType toV2() {
    if (base.directoryName != null) {
      return GeneralSubtreeType.ofDirectoryName(base.directoryName);
    } else if (base.dnsName != null) {
      return GeneralSubtreeType.ofDnsName(base.dnsName);
    } else if (base.uri != null) {
      return GeneralSubtreeType.ofUri(base.uri);
    } else if (base.ipAddress != null) {
      return GeneralSubtreeType.ofIpAddress(base.ipAddress);
    } else if (base.rfc822Name != null) {
      return GeneralSubtreeType.ofRfc822Name(base.rfc822Name);
    } else {
      throw new IllegalStateException("unknown GeneralSubtreeType field");
    }
  }

  public static V1GeneralSubtreeType parse(JsonMap json)
      throws CodecException {
    Base base = Base.parse(json.getNnMap("base"));
    return new V1GeneralSubtreeType(base);
  }

  public static List<V1GeneralSubtreeType> parseList(JsonList json)
      throws CodecException {
    List<V1GeneralSubtreeType> ret = new ArrayList<>(json.size());
    for (JsonMap v : json.toMapList()) {
      ret.add(parse(v));
    }
    return ret;
  }

}
