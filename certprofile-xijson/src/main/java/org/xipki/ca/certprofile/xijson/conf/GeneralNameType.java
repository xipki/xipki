// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.ca.api.profile.Certprofile.GeneralNameMode;
import org.xipki.ca.api.profile.Certprofile.GeneralNameTag;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.StringUtil;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Configuration of GeneralName.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class GeneralNameType extends ValidatableConf {

  private List<String> modes;

  public List<String> getModes() {
    if (modes == null) {
      modes = new LinkedList<>();
    }
    return modes;
  }

  public void setModes(List<String> modes) {
    this.modes = modes;
  }

  public Set<GeneralNameMode> toGeneralNameModes() throws CertprofileException {
    if (modes == null || modes.isEmpty()) {
      throw new CertprofileException("GeneralNameType may not be empty");
    }

    Set<GeneralNameMode> ret = new HashSet<>();
    for (String m : modes) {
      if (StringUtil.startsWithIgnoreCase(m, "otherName:")) {
        String[] oids = m.substring("otherName:".length()).split(",");
        Set<ASN1ObjectIdentifier> set = new HashSet<>();
        for (String oid : oids) {
          set.add(new ASN1ObjectIdentifier(oid));
        }

        ret.add(new GeneralNameMode(GeneralNameTag.otherName, set));
      } else {
        for (GeneralNameTag tag : GeneralNameTag.values()) {
          if (tag != GeneralNameTag.otherName && tag.name().equalsIgnoreCase(m)) {
            ret.add(new GeneralNameMode(tag));
          }
        }
      }
    }

    if (ret.isEmpty()) {
      throw new CertprofileException("GeneralNameType may not be empty");
    }

    return ret;
  } // method toGeneralNameModes

  public void addTags(GeneralNameTag... tags) {
    for (GeneralNameTag tag : tags) {
      if (tag == GeneralNameTag.otherName) {
        throw new IllegalArgumentException("tag otherName  is not allowed");
      }
    }

    for (GeneralNameTag tag : tags) {
      getModes().add(tag.name());
    }
  } // method addTags

  public void addOtherNames(DescribableOid... oids) {
    StringBuilder sb = new StringBuilder("otherName:");
    for (int i = 0; i < oids.length; i++) {
      if (i != 0) {
        sb.append(",");
      }
      sb.append(oids[i].getOid());
    }
    getModes().add(sb.toString());
  } // method addOtherNames

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(modes, "modes");
  }
}
