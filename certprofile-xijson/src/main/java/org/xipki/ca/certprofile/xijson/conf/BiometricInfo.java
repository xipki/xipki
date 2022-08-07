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
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableInt;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.TripleState;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.LinkedList;
import java.util.List;

/**
 * Extension BiometricInfo.
 *
 * @author Lijun Liao
 */

public class BiometricInfo extends ValidatableConf {

  public static class BiometricTypeType extends ValidatableConf {

    @JSONField(ordinal = 1)
    private DescribableInt predefined;

    @JSONField(ordinal = 2)
    private DescribableOid oid;

    public DescribableInt getPredefined() {
      return predefined;
    }

    public void setPredefined(DescribableInt predefined) {
      this.predefined = predefined;
    }

    public DescribableOid getOid() {
      return oid;
    }

    public void setOid(DescribableOid oid) {
      this.oid = oid;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      notNull(oid, "oid");
      notNull(predefined, "predefined");
    }

  } // class BiometricTypeType

  @JSONField(ordinal = 1)
  private List<BiometricTypeType> types;

  @JSONField(ordinal = 2)
  private List<DescribableOid> hashAlgorithms;

  @JSONField(ordinal = 3)
  private TripleState includeSourceDataUri;

  public List<BiometricTypeType> getTypes() {
    if (types == null) {
      types = new LinkedList<>();
    }
    return types;
  }

  public void setTypes(List<BiometricTypeType> types) {
    this.types = types;
  }

  public List<DescribableOid> getHashAlgorithms() {
    if (hashAlgorithms == null) {
      hashAlgorithms = new LinkedList<>();
    }
    return hashAlgorithms;
  }

  public void setHashAlgorithms(List<DescribableOid> hashAlgorithms) {
    this.hashAlgorithms = hashAlgorithms;
  }

  public TripleState getIncludeSourceDataUri() {
    return includeSourceDataUri;
  }

  public void setIncludeSourceDataUri(TripleState includeSourceDataUri) {
    this.includeSourceDataUri = includeSourceDataUri;
  }

  @Override
  public void validate()
      throws InvalidConfException {
    notEmpty(hashAlgorithms, "hashAlgorithms");
    notEmpty(types, "types");
    notNull(includeSourceDataUri, "includeSourceDataUri");
  }

} // class BiometricInfo
