// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Control the permitted public key in the certificate.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class KeyParametersOption {

  public static class AllowAllParametersOption extends KeyParametersOption {
  } // class AllowAllParametersOption

  public static class RSAParametersOption extends KeyParametersOption {

    private Set<Integer> modulusLengths;

    public RSAParametersOption() {
    }

    public void setModulusLengths(Collection<Integer> modulusLengths) {
      this.modulusLengths = (CollectionUtil.isEmpty(modulusLengths)) ? null : new HashSet<>(modulusLengths);
    }

    public boolean allowsModulusLength(int modulusLength) {
      return modulusLengths == null || modulusLengths.contains(modulusLength);
    }

  } // class RSAParametersOption

  public static class DSAParametersOption extends KeyParametersOption {

    private Set<Integer> plengths;

    private Set<Integer> qlengths;

    public DSAParametersOption() {
    }

    public void setPlengths(Collection<Integer> plengths) {
      this.plengths = CollectionUtil.isEmpty(plengths) ? null : new HashSet<>(plengths);
    }

    public void setQlengths(Collection<Integer> qlengths) {
      this.qlengths = CollectionUtil.isEmpty(qlengths) ? null : new HashSet<>(qlengths);
    }

    public boolean allowsPlength(int plength) {
      return plengths == null || plengths.contains(plength);
    }

    public boolean allowsQlength(int qlength) {
      return qlengths == null || qlengths.contains(qlength);
    }

  } // class DSAParametersOption

  public static class ECParamatersOption extends KeyParametersOption {

    private Set<ASN1ObjectIdentifier> curveOids;

    private Set<Byte> pointEncodings;

    public ECParamatersOption() {
    }

    public Set<ASN1ObjectIdentifier> curveOids() {
      return curveOids;
    }

    public void setCurveOids(Set<ASN1ObjectIdentifier> curveOids) {
      this.curveOids = curveOids;
    }

    public Set<ASN1ObjectIdentifier> getCurveOids() {
      return curveOids;
    }

    public void setPointEncodings(Set<Byte> pointEncodings) {
      this.pointEncodings = pointEncodings;
    }

    public Set<Byte> getPointEncodings() {
      return pointEncodings;
    }

    public boolean allowsCurve(ASN1ObjectIdentifier curveOid) {
      return curveOids == null || curveOids.contains(Args.notNull(curveOid, "curveOid"));
    }

    public boolean allowsPointEncoding(byte encoding) {
      return pointEncodings == null || pointEncodings.contains(encoding);
    }

  } // class ECParamatersOption

  public static final AllowAllParametersOption ALLOW_ALL = new AllowAllParametersOption();

  private KeyParametersOption() {
  }

}
