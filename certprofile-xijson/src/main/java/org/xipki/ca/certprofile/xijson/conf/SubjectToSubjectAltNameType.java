/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.certprofile.xijson.conf;

import com.alibaba.fastjson.annotation.JSONField;
import org.xipki.ca.api.profile.Certprofile.GeneralNameTag;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.Arrays;
import java.util.List;

/**
 * Control which RDNs and how they are converted to the SubjectAltNames extension.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class SubjectToSubjectAltNameType extends ValidatableConf {

  private static final List<GeneralNameTag> allowedTargets = Arrays.asList(
      GeneralNameTag.rfc822Name,                GeneralNameTag.DNSName,   GeneralNameTag.directoryName,
      GeneralNameTag.uniformResourceIdentifier, GeneralNameTag.IPAddress, GeneralNameTag.registeredID);

  @JSONField(ordinal = 1)
  private DescribableOid source;

  @JSONField(ordinal = 2)
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
