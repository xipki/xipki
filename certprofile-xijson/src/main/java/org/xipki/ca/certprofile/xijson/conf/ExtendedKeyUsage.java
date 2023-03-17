// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.ca.api.profile.Certprofile.ExtKeyUsageControl;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.*;

/**
 * Extension ExtendedKeyUsage.
 *
 * @author Lijun Liao (xipki)
 */

public class ExtendedKeyUsage extends ValidatableConf {

  private List<Usage> usages;

  public List<Usage> getUsages() {
    if (usages == null) {
      usages = new LinkedList<>();
    }
    return usages;
  }

  public void setUsages(List<Usage> usages) {
    this.usages = usages;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(usages, "usages");
    validate(usages);
  }

  public Set<ExtKeyUsageControl> toXiExtKeyUsageOptions() {
    List<Usage> usages = getUsages();
    Set<ExtKeyUsageControl> controls = new HashSet<>();

    for (Usage m : usages) {
      controls.add(new ExtKeyUsageControl(new ASN1ObjectIdentifier(m.getOid()), m.isRequired()));
    }

    return Collections.unmodifiableSet(controls);
  } // method buildExtKeyUsageOptions

  public static class Usage extends DescribableOid {

    private boolean required;

    public boolean isRequired() {
      return required;
    }

    public void setRequired(boolean required) {
      this.required = required;
    }

  } // class Usage

} // class ExtendedKeyUsage
