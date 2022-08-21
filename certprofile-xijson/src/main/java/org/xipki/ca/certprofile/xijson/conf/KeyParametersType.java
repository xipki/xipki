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
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.ca.api.profile.KeyParametersOption;
import org.xipki.ca.api.profile.Range;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * KeyPrameters.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class KeyParametersType extends ValidatableConf {

  public static class DsaParametersType extends ValidatableConf {

    private List<Range> plengths;

    private List<Range> qlengths;

    public List<Range> getPlengths() {
      if (plengths == null) {
        plengths = new LinkedList<>();
      }
      return plengths;
    }

    public void setPlengths(List<Range> plengths) {
      if (qlengths == null) {
        qlengths = new LinkedList<>();
      }
      this.plengths = plengths;
    }

    public List<Range> getQlengths() {
      return qlengths;
    }

    public void setQlengths(List<Range> qlengths) {
      this.qlengths = qlengths;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      validateRanges(plengths);
      validateRanges(qlengths);
    }

  } // class DsaParametersType

  public static class EcParametersType extends ValidatableConf {

    private List<DescribableOid> curves;

    private List<Byte> pointEncodings;

    public List<DescribableOid> getCurves() {
      if (curves == null) {
        curves = new LinkedList<>();
      }
      return curves;
    }

    public void setCurves(List<DescribableOid> curves) {
      this.curves = curves;
    }

    public List<Byte> getPointEncodings() {
      if (pointEncodings == null) {
        pointEncodings = new LinkedList<>();
      }
      return pointEncodings;
    }

    public void setPointEncodings(List<Byte> pointEncodings) {
      this.pointEncodings = pointEncodings;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      validate(curves);
    }

  } // class EcParametersType

  public static class RsaParametersType extends ValidatableConf {

    @JSONField(ordinal = 1)
    private List<Range> modulusLengths;

    public List<Range> getModulusLengths() {
      if (modulusLengths == null) {
        modulusLengths = new LinkedList<>();
      }
      return modulusLengths;
    }

    public void setModulusLengths(List<Range> modulusLengths) {
      this.modulusLengths = modulusLengths;
    }

    @Override
    public void validate()
        throws InvalidConfException {
      validateRanges(modulusLengths);
    }

  } // class RsaParametersType

  private DsaParametersType dsa;

  private EcParametersType ec;

  private RsaParametersType rsa;

  public DsaParametersType getDsa() {
    return dsa;
  }

  public void setDsa(DsaParametersType dsa) {
    this.dsa = dsa;
  }

  public EcParametersType getEc() {
    return ec;
  }

  public void setEc(EcParametersType ec) {
    this.ec = ec;
  }

  public RsaParametersType getRsa() {
    return rsa;
  }

  public void setRsa(RsaParametersType rsa) {
    this.rsa = rsa;
  }

  public KeyParametersOption toXiKeyParametersOption() {
    if (ec != null) {
      KeyParametersOption.ECParamatersOption option = new KeyParametersOption.ECParamatersOption();

      if (ec.getCurves() != null) {
        List<DescribableOid> curves = ec.getCurves();
        Set<ASN1ObjectIdentifier> curveOids = X509ProfileType.toOidSet(curves);
        option.setCurveOids(curveOids);
      }

      if (ec.getPointEncodings() != null) {
        List<Byte> bytes = ec.getPointEncodings();
        Set<Byte> pointEncodings = new HashSet<>(bytes);
        option.setPointEncodings(pointEncodings);
      }
      return option;
    } else if (rsa != null) {
      KeyParametersOption.RSAParametersOption option = new KeyParametersOption.RSAParametersOption();
      option.setModulusLengths(buildParametersMap(rsa.getModulusLengths()));
      return option;
    } else if (dsa != null) {
      KeyParametersOption.DSAParametersOption option = new KeyParametersOption.DSAParametersOption();
      option.setPlengths(buildParametersMap(dsa.getPlengths()));
      option.setQlengths(buildParametersMap(dsa.getQlengths()));
      return option;
    } else {
      return KeyParametersOption.ALLOW_ALL;
    }
  } // method toXiKeyParametersOption

  private static Set<Range> buildParametersMap(List<Range> ranges) {
    if (CollectionUtil.isEmpty(ranges)) {
      return null;
    }

    Set<Range> ret = new HashSet<>();
    for (Range range : ranges) {
      if (range.getMin() != null || range.getMax() != null) {
        ret.add(new Range(range.getMin(), range.getMax()));
      }
    }

    return ret;
  } // method buildParametersMap

  private static void validateRanges(List<Range> ranges)
      throws InvalidConfException {
    if (ranges != null) {
      for (Range r : ranges) {
        try {
          r.validate();
        } catch (IllegalArgumentException ex) {
          throw new InvalidConfException(ex.getMessage());
        }
      }
    }
  } // method validateRanges

  @Override
  public void validate()
      throws InvalidConfException {
    validate(dsa);
    validate(ec);
    validate(rsa);
  } // method validate

}
