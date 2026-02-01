// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.conf.InvalidConfException;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration of GeneralSubtree.
 *
 * @author Lijun Liao (xipki)
 *
 */

public class GeneralSubtreeType implements JsonEncodable {

  private String rfc822Name;

  private String dnsName;

  private String directoryName;

  private String uri;

  private String ipAddress;

  public String rfc822Name() {
    return rfc822Name;
  }

  private GeneralSubtreeType() {
  }

  public static GeneralSubtreeType ofRfc822Name(String rfc822Name) {
    GeneralSubtreeType ret = new GeneralSubtreeType();
    ret.rfc822Name = Args.notBlank(rfc822Name, "");
    return ret;
  }

  public String dnsName() {
    return dnsName;
  }

  public static GeneralSubtreeType ofDnsName(String dnsName) {
    GeneralSubtreeType ret = new GeneralSubtreeType();
    ret.dnsName = Args.notBlank(dnsName, "dnsName");
    return ret;
  }

  public String directoryName() {
    return directoryName;
  }

  public static GeneralSubtreeType ofDirectoryName(String directoryName) {
    GeneralSubtreeType ret = new GeneralSubtreeType();
    ret.directoryName = Args.notBlank(directoryName, "directoryName");
    return ret;
  }

  public String uri() {
    return uri;
  }

  public static GeneralSubtreeType ofUri(String uri) {
    GeneralSubtreeType ret = new GeneralSubtreeType();
    ret.uri = Args.notBlank(uri, "uri");
    return ret;
  }

  public String ipAddress() {
    return ipAddress;
  }

  public static GeneralSubtreeType ofIpAddress(String ipAddress) {
    GeneralSubtreeType ret = new GeneralSubtreeType();
    ret.ipAddress = Args.notBlank(ipAddress, "ipAddress");
    return ret;
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
      throw new InvalidConfException("exact one of directoryName, dnsName, " +
          "ipAddress, rfc822Name, and uri must be set");
    }
  } // method validate

  @Override
  public JsonMap toCodec() {
    return new JsonMap().put("rfc822Name", rfc822Name)
        .put("dnsName", dnsName).put("directoryName", directoryName)
        .put("uri", uri).put("ipAddress", ipAddress);
  }

  public static GeneralSubtreeType parse(JsonMap json) throws CodecException {
    String str = json.getString("rfc822Name");
    if (str != null) {
      return ofRfc822Name(str);
    }

    str = json.getString("dnsName");
    if (str != null) {
      return ofDnsName(str);
    }

    str = json.getString("directoryName");
    if (str != null) {
      return ofDirectoryName(str);
    }

    str = json.getString("uri");
    if (str != null) {
      return ofUri(str);
    }

    str = json.getNnString("ipAddress");
    return ofIpAddress(str);
  }

  public static List<GeneralSubtreeType> parse(JsonList list)
      throws CodecException {
    List<GeneralSubtreeType> ret = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      ret.add(GeneralSubtreeType.parse(v));
    }
    return ret;
  }

}
