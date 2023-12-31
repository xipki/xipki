// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.ca.api.profile.Certprofile.GeneralNameTag;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.Arrays;
import java.util.List;

/**
 * Control which RDNs and how they are converted to the SubjectAltNames extension.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class SubjectToSubjectAltNameType extends ValidableConf {

  private static final List<GeneralNameTag> allowedTargets = Arrays.asList(
      GeneralNameTag.rfc822Name,                GeneralNameTag.DNSName,   GeneralNameTag.directoryName,
      GeneralNameTag.uniformResourceIdentifier, GeneralNameTag.IPAddress, GeneralNameTag.registeredID);

  private DescribableOid source;

  private GeneralNameTag target;

  public DescribableOid getSource() {
    return source;
  }

  public void setSource(DescribableOid source) {
    this.source = source;
  }

  public GeneralNameTag getTarget() {
    return target;
  }

  public void setTarget(GeneralNameTag target) {
    if (target != null && !allowedTargets.contains(target)) {
      throw new IllegalArgumentException("invalid target " + target);
    }
    this.target = target;
  }

  @Override
  public void validate() throws InvalidConfException {
    notNull(source, "source");
    validate(source);
    notNull(target, "target");
    if (!allowedTargets.contains(target)) {
      throw new InvalidConfException("target " + target + " is not allowed");
    }
  }

}
