// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.sdk;

import org.xipki.security.util.JSON;

import java.util.List;

/**
 *
 * @author Lijun Liao (xipki)
 * @since 6.4.0
 */

public class CaNameResponse extends SdkResponse {

  private String name;

  private List<String> aliases;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public List<String> getAliases() {
    return aliases;
  }

  public void setAliases(List<String> aliases) {
    this.aliases = aliases;
  }

  public static CaNameResponse decode(byte[] encoded) {
    return JSON.parseObject(encoded, CaNameResponse.class);
  }

}
