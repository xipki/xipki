// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.xipki.ca.api.profile.ctrl.KeySingleUsage;
import org.xipki.security.KeySpec;
import org.xipki.util.codec.Args;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * @author Lijun Liao (xipki)
 */
public class KeyUsageControl {

  private final KeySingleUsages defaultUsages;

  private final List<KeySingleUsages> usagesList;

  public KeyUsageControl(List<KeySingleUsages> usagesList) {
    this.usagesList = Args.notEmpty(usagesList, "usagesList");

    KeySingleUsages dflt = null;
    for (KeySingleUsages usages : usagesList) {
      if (usages.appliesTo == null) {
        dflt = usages;
      }
    }

    this.defaultUsages = dflt;
  }

  public Set<KeySingleUsage> getUsages(KeySpec keySpec) {
    for (KeySingleUsages usages : usagesList) {
      if (usages.appliesTo != null && usages.appliesTo.contains(keySpec)) {
        return usages.singleUsages;
      }
    }

    return defaultUsages == null ? null : defaultUsages.singleUsages;
  }

  public static class KeySingleUsages {

    private final List<KeySpec> appliesTo;

    private final Set<KeySingleUsage> singleUsages;

    public KeySingleUsages(List<KeySpec> appliesTo,
                           Set<KeySingleUsage> singleUsages) {
      this.appliesTo = appliesTo;
      this.singleUsages = Collections.unmodifiableSet(singleUsages);
    }
  }

}
