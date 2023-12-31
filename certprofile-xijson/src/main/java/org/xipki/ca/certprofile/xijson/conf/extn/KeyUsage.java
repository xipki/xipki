// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.ca.api.profile.Certprofile.KeyUsageControl;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Extension KeyUsage.
 *
 * @author Lijun Liao (xipki)
 */

public class KeyUsage extends ValidableConf {

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

  public Set<KeyUsageControl> toXiKeyUsageOptions() {
    List<Usage> usages = getUsages();
    Set<KeyUsageControl> controls = new HashSet<>();

    for (Usage m : usages) {
      controls.add(new KeyUsageControl(m.getValue(), m.isRequired()));
    }

    return Collections.unmodifiableSet(controls);
  } // method toXiKeyUsageOptions

  public static class Usage extends ValidableConf {

    private String value;

    private boolean required;

    public String getValue() {
      return value;
    }

    public void setValue(String value) {
      this.value = value;
    }

    public boolean isRequired() {
      return required;
    }

    public void setRequired(boolean required) {
      this.required = required;
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  } // class Usage

} // class KeyUsage
