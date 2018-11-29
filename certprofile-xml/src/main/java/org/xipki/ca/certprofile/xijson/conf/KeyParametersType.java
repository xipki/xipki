/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.KeyParametersOption;
import org.xipki.ca.api.profile.Range;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.CollectionUtil;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

import com.alibaba.fastjson.annotation.JSONField;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class KeyParametersType extends ValidatableConf {

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
    public void validate() throws InvalidConfException {
      validate(curves);
    }

  }

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
    public void validate() throws InvalidConfException {
      validateRanges(modulusLengths);
    }

  }

  public static class RsapssParametersType extends RsaParametersType {

    @JSONField(ordinal = 2)
    private List<DescribableOid> hashAlgorithms;

    @JSONField(ordinal = 3)
    private List<DescribableOid> maskGenAlgorithms;

    @JSONField(ordinal = 4)
    private List<Integer> saltLengths;

    @JSONField(ordinal = 5)
    private List<Integer> trailerFields;

    public List<DescribableOid> getHashAlgorithms() {
      if (hashAlgorithms == null) {
        hashAlgorithms = new LinkedList<>();
      }
      return hashAlgorithms;
    }

    public void setHashAlgorithms(List<DescribableOid> hashAlgorithms) {
      this.hashAlgorithms = hashAlgorithms;
    }

    public List<DescribableOid> getMaskGenAlgorithms() {
      if (maskGenAlgorithms == null) {
        maskGenAlgorithms = new LinkedList<>();
      }
      return maskGenAlgorithms;
    }

    public void setMaskGenAlgorithms(List<DescribableOid> maskGenAlgorithms) {
      this.maskGenAlgorithms = maskGenAlgorithms;
    }

    public List<Integer> getSaltLengths() {
      if (saltLengths == null) {
        saltLengths = new LinkedList<>();
      }
      return saltLengths;
    }

    public void setSaltLengths(List<Integer> saltLengths) {
      this.saltLengths = saltLengths;
    }

    public List<Integer> getTrailerFields() {
      if (trailerFields == null) {
        trailerFields = new LinkedList<>();
      }
      return trailerFields;
    }

    public void setTrailerFields(List<Integer> trailerFields) {
      this.trailerFields = trailerFields;
    }

    @Override
    public void validate() throws InvalidConfException {
      validate(hashAlgorithms);
      validate(maskGenAlgorithms);
    }

  }

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
    public void validate() throws InvalidConfException {
      validateRanges(plengths);
      validateRanges(qlengths);
    }

  }

  public static class GostParametersType extends ValidatableConf {

    private List<DescribableOid> publicKeyParamSet;

    private List<DescribableOid> digestParamSet;

    private List<DescribableOid> encryptionParamSet;

    public List<DescribableOid> getPublicKeyParamSet() {
      if (publicKeyParamSet == null) {
        publicKeyParamSet = new LinkedList<>();
      }
      return publicKeyParamSet;
    }

    public void setPublicKeyParamSet(List<DescribableOid> publicKeyParamSet) {
      this.publicKeyParamSet = publicKeyParamSet;
    }

    public List<DescribableOid> getDigestParamSet() {
      if (digestParamSet == null) {
        digestParamSet = new LinkedList<>();
      }
      return digestParamSet;
    }

    public void setDigestParamSet(List<DescribableOid> digestParamSet) {
      this.digestParamSet = digestParamSet;
    }

    public List<DescribableOid> getEncryptionParamSet() {
      if (encryptionParamSet == null) {
        encryptionParamSet = new LinkedList<>();
      }
      return encryptionParamSet;
    }

    public void setEncryptionParamSet(List<DescribableOid> encryptionParamSet) {
      this.encryptionParamSet = encryptionParamSet;
    }

    @Override
    public void validate() throws InvalidConfException {
      // TODO Auto-generated method stub
    }

  }

  private DsaParametersType dsa;

  private EcParametersType ec;

  private GostParametersType gost;

  private RsaParametersType rsa;

  private RsapssParametersType rsapss;

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

  public GostParametersType getGost() {
    return gost;
  }

  public void setGost(GostParametersType gost) {
    this.gost = gost;
  }

  public RsaParametersType getRsa() {
    return rsa;
  }

  public void setRsa(RsaParametersType rsa) {
    this.rsa = rsa;
  }

  public RsapssParametersType getRsapss() {
    return rsapss;
  }

  public void setRsapss(RsapssParametersType rsapss) {
    this.rsapss = rsapss;
  }

  public KeyParametersOption toXiKeyParametersOption()
      throws CertprofileException {
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
      KeyParametersOption.RSAParametersOption option =
          new KeyParametersOption.RSAParametersOption();
      option.setModulusLengths(buildParametersMap(rsa.getModulusLengths()));
      return option;
    } else if (rsapss != null) {
      KeyParametersOption.RSAPSSParametersOption option =
          new KeyParametersOption.RSAPSSParametersOption();

      Set<Range> modulusLengths = buildParametersMap(rsapss.getModulusLengths());
      option.setModulusLengths(modulusLengths);
      option.setHashAlgs(X509ProfileType.toOidSet(rsapss.getHashAlgorithms()));
      option.setMaskGenAlgs(X509ProfileType.toOidSet(rsapss.getMaskGenAlgorithms()));
      option.setSaltLengths(new HashSet<>(rsapss.getSaltLengths()));
      option.setTrailerFields(new HashSet<>(rsapss.getTrailerFields()));

      return option;
    } else if (dsa != null) {
      KeyParametersOption.DSAParametersOption option =
          new KeyParametersOption.DSAParametersOption();

      option.setPlengths(buildParametersMap(dsa.getPlengths()));
      option.setQlengths(buildParametersMap(dsa.getQlengths()));

      return option;
    } else if (gost != null) {
      KeyParametersOption.GostParametersOption option =
          new KeyParametersOption.GostParametersOption();

      option.setPublicKeyParamSets(X509ProfileType.toOidSet(gost.getPublicKeyParamSet()));
      option.setDigestParamSets(X509ProfileType.toOidSet(gost.getDigestParamSet()));
      option.setEncryptionParamSets(X509ProfileType.toOidSet(gost.getEncryptionParamSet()));

      return option;
    } else {
      return KeyParametersOption.ALLOW_ALL;
    }
  } // method convertKeyParametersOption

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
  }

  private static void validateRanges(List<Range> ranges) throws InvalidConfException {
    if (ranges != null) {
      for (Range r : ranges) {
        try {
          r.validate();
        } catch (IllegalArgumentException ex) {
          throw new InvalidConfException(ex.getMessage());
        }
      }
    }
  }

  @Override
  public void validate() throws InvalidConfException {
    validate(dsa);
    validate(ec);
    validate(gost);
    validate(rsa);
    validate(rsapss);
  }

}
