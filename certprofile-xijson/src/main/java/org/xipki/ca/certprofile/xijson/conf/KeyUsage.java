// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.ca.api.profile.Certprofile.KeyUsageControl;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.*;

/**
 * Extension KeyUsage.
 *
 * @author Lijun Liao (xipki)
 */

public class KeyUsage extends ValidatableConf {

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

  public static class Usage extends ValidatableConf {

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
