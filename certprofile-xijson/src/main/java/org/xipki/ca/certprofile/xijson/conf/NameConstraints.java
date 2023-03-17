// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.security.util.X509Util;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

/**
 * Extension NameConstraints.
 * Only for CA, at least one of permittedSubtrees and excludedSubtrees must be present.
 * @author Lijun Liao (xipki)
 */
public class NameConstraints extends ValidatableConf {

  private List<GeneralSubtreeType> permittedSubtrees;

  private List<GeneralSubtreeType> excludedSubtrees;

  public List<GeneralSubtreeType> getPermittedSubtrees() {
    if (permittedSubtrees == null) {
      permittedSubtrees = new LinkedList<>();
    }
    return permittedSubtrees;
  }

  public void setPermittedSubtrees(List<GeneralSubtreeType> permittedSubtrees) {
    this.permittedSubtrees = permittedSubtrees;
  }

  public List<GeneralSubtreeType> getExcludedSubtrees() {
    if (excludedSubtrees == null) {
      excludedSubtrees = new LinkedList<>();
    }
    return excludedSubtrees;
  }

  public void setExcludedSubtrees(List<GeneralSubtreeType> excludedSubtrees) {
    this.excludedSubtrees = excludedSubtrees;
  }

  @Override
  public void validate() throws InvalidConfException {
    if (CollectionUtil.isEmpty(permittedSubtrees) && CollectionUtil.isEmpty(excludedSubtrees)) {
      throw new InvalidConfException("permittedSubtrees and excludedSubtrees may not be both null");
    }
    validate(permittedSubtrees, excludedSubtrees);
  } // method validate

  public org.bouncycastle.asn1.x509.NameConstraints toXiNameConstraints()
      throws CertprofileException {
    GeneralSubtree[] permitted = buildGeneralSubtrees(getPermittedSubtrees());
    GeneralSubtree[] excluded = buildGeneralSubtrees(getExcludedSubtrees());
    return (permitted == null && excluded == null) ? null
        : new org.bouncycastle.asn1.x509.NameConstraints(permitted, excluded);
  } // method toXiNameConstraints

  private static GeneralSubtree[] buildGeneralSubtrees(List<GeneralSubtreeType> subtrees)
      throws CertprofileException {
    if (CollectionUtil.isEmpty(subtrees)) {
      return null;
    }

    final int n = subtrees.size();
    GeneralSubtree[] ret = new GeneralSubtree[n];
    for (int i = 0; i < n; i++) {
      ret[i] = buildGeneralSubtree(subtrees.get(i));
    }

    return ret;
  } // method buildGeneralSubtrees

  private static GeneralSubtree buildGeneralSubtree(GeneralSubtreeType type) throws CertprofileException {
    GeneralSubtreeType.Base baseType = Args.notNull(type, "type").getBase();
    GeneralName base;
    if (baseType.getDirectoryName() != null) {
      base = new GeneralName(X509Util.reverse(new X500Name(baseType.getDirectoryName())));
    } else if (baseType.getDnsName() != null) {
      base = new GeneralName(GeneralName.dNSName, baseType.getDnsName());
    } else if (baseType.getIpAddress() != null) {
      base = new GeneralName(GeneralName.iPAddress, baseType.getIpAddress());
    } else if (baseType.getRfc822Name() != null) {
      base = new GeneralName(GeneralName.rfc822Name, baseType.getRfc822Name());
    } else if (baseType.getUri() != null) {
      base = new GeneralName(GeneralName.uniformResourceIdentifier, baseType.getUri());
    } else {
      throw new IllegalStateException("should not reach here, unknown child of GeneralSubtreeType");
    }

    Integer min = type.getMinimum();
    if (min != null && min < 0) {
      throw new CertprofileException("negative minimum is not allowed: " + min);
    }
    BigInteger minimum = (min == null) ? null : BigInteger.valueOf(min);

    Integer max = type.getMaximum();
    if (max != null && max < 0) {
      throw new CertprofileException("negative maximum is not allowed: " + max);
    }
    BigInteger maximum = (max == null) ? null : BigInteger.valueOf(max);

    return new GeneralSubtree(base, minimum, maximum);
  } // method buildGeneralSubtree

} // class NameConstraints
