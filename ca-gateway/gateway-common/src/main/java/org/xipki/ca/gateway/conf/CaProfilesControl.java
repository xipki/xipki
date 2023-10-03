// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.ca.gateway.conf;

import org.xipki.util.exception.InvalidConfException;

import java.util.HashSet;
import java.util.Set;

/**
 * Gateway's CA-Profiles.
 *
 * @author Lijun Liao (xipki)
 * @since 6.4.0
 */
public class CaProfilesControl {

  private final CaProfileConf[] caProfiles;

  public CaProfilesControl(CaProfileConf[] caProfiles) {
    if (caProfiles == null) {
      this.caProfiles = new CaProfileConf[0];
    } else {
      for (CaProfileConf conf : caProfiles) {
        if (conf == null) {
          throw new IllegalArgumentException("caProfiles must not contain null element");
        }
      }
      this.caProfiles = caProfiles;
    }
  }

  public CaProfileConf getCaProfile(String name) {
    for (CaProfileConf conf : caProfiles) {
      if (conf.getName().equalsIgnoreCase(name)) {
        return conf;
      }
    }
    return null;
  }

  public void validate() throws InvalidConfException {
    Set<String> names = new HashSet<>();
    for (CaProfileConf entry : caProfiles) {
      String name = entry.getName();
      checkName(name, "caProfile name");
      if (names.contains(name)) {
        throw new InvalidConfException("caProfile " + name + " duplicated");
      }

      names.add(name);
      entry.validate();
    }
  }

  private static void checkName(String param, String paramName) throws InvalidConfException {
    if (param == null || param.isEmpty()) {
      throw new InvalidConfException(paramName + " must not be blank");
    }

    for (int i = 0; i < param.length(); i++) {
      char c = param.charAt(i);
      if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
          || (c == '-') || (c == '_') || (c == '.')) {
        continue;
      }

      throw new InvalidConfException("invalid char '" + c + "' in " + paramName);
    }
  }

}

