// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableInt;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.TripleState;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.LinkedList;
import java.util.List;

/**
 * Extension BiometricInfo.
 *
 * @author Lijun Liao (xipki)
 */

public class BiometricInfo extends ValidableConf {

  public static class BiometricTypeType extends ValidableConf {

    private DescribableInt predefined;

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
    public void validate() throws InvalidConfException {
      notNull(oid, "oid");
      notNull(predefined, "predefined");
    }

  } // class BiometricTypeType

  private List<BiometricTypeType> types;

  private List<DescribableOid> hashAlgorithms;

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
  public void validate() throws InvalidConfException {
    notEmpty(hashAlgorithms, "hashAlgorithms");
    notEmpty(types, "types");
    notNull(includeSourceDataUri, "includeSourceDataUri");
  }

} // class BiometricInfo
