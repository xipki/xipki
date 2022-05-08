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

package org.xipki.ca.api.profile;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;

import java.util.HashSet;
import java.util.Set;

/**
 * Control the permitted public key in the certificate.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class KeyParametersOption {

  public static class AllowAllParametersOption extends KeyParametersOption {
  } // class AllowAllParametersOption

  public static class RSAParametersOption extends KeyParametersOption {

    private Set<Range> modulusLengths;

    public RSAParametersOption() {
    }

    public void setModulusLengths(Set<Range> modulusLengths) {
      this.modulusLengths = (CollectionUtil.isEmpty(modulusLengths)) ? null
          : new HashSet<>(modulusLengths);
    }

    public boolean allowsModulusLength(int modulusLength) {
      if (modulusLengths == null) {
        return true;
      }

      for (Range range : modulusLengths) {
        if (range.match(modulusLength)) {
          return true;
        }
      }
      return false;
    }

  } // class RSAParametersOption

  public static class DSAParametersOption extends KeyParametersOption {

    private Set<Range> plengths;

    private Set<Range> qlengths;

    public DSAParametersOption() {
    }

    public void setPlengths(Set<Range> plengths) {
      this.plengths = CollectionUtil.isEmpty(plengths) ? null : new HashSet<>(plengths);
    }

    public void setQlengths(Set<Range> qlengths) {
      this.qlengths = CollectionUtil.isEmpty(qlengths) ? null : new HashSet<>(qlengths);
    }

    public boolean allowsPlength(int plength) {
      if (plengths == null) {
        return true;
      }

      for (Range range : plengths) {
        if (range.match(plength)) {
          return true;
        }
      }

      return false;
    }

    public boolean allowsQlength(int qlength) {
      if (qlengths == null) {
        return true;
      }

      for (Range range : qlengths) {
        if (range.match(qlength)) {
          return true;
        }
      }

      return false;
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
      Args.notNull(curveOid, "curveOid");
      return curveOids == null || curveOids.contains(curveOid);
    }

    public boolean allowsPointEncoding(byte encoding) {
      return pointEncodings == null || pointEncodings.contains(encoding);
    }

  } // class ECParamatersOption

  public static final AllowAllParametersOption ALLOW_ALL = new AllowAllParametersOption();

  private KeyParametersOption() {
  }

}
