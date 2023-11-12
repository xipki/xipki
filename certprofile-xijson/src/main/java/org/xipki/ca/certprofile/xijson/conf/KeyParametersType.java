// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.ca.api.profile.KeyParametersOption;
import org.xipki.ca.api.profile.Range;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ValidableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;

/**
 * KeyPrameters.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class KeyParametersType extends ValidableConf {

  public static class DsaParametersType extends ValidableConf {

    private List<Integer> p;

    private List<Integer> q;

    public List<Integer> getP() {
      return p;
    }

    public void setP(List<Integer> p) {
      this.p = p;
    }

    public List<Integer> getQ() {
      return q;
    }

    public void setQ(List<Integer> q) {
      this.q = q;
    }

    @Deprecated
    public void setPlengths(List<Range> plengths) {
      if (CollectionUtil.isNotEmpty(plengths)) {
        this.p = new LinkedList<>();
        for (Range r : plengths) {
          for (int i = r.getMin(); i < r.getMax(); i++) {
            this.p.add(i);
          }
        }
      }
    }

    @Deprecated
    public void setQlengths(List<Range> qlengths) {
      if (CollectionUtil.isNotEmpty(qlengths)) {
        this.q = new LinkedList<>();
        for (Range r : qlengths) {
          for (int i = r.getMin(); i < r.getMax(); i++) {
            this.q.add(i);
          }
        }
      }
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  } // class DsaParametersType

  public static class EcParametersType extends ValidableConf {

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

  } // class EcParametersType

  public static class RsaParametersType extends ValidableConf {

    private List<Integer> modulus;

    public List<Integer> getModulus() {
      return modulus;
    }

    public void setModulus(List<Integer> modulus) {
      this.modulus = modulus;
    }

    @Deprecated
    public void setModulusLengths(List<Range> modulusLengths) {
      if (CollectionUtil.isNotEmpty(modulusLengths)) {
        this.modulus = new LinkedList<>();
        for (Range r : modulusLengths) {
          for (int i = r.getMin(); i < r.getMax(); i++) {
            this.modulus.add(i);
          }
        }
      }
    }

    @Override
    public void validate() throws InvalidConfException {
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
        option.setCurveOids(X509ProfileType.toOidSet(ec.getCurves()));
      }

      if (ec.getPointEncodings() != null) {
        option.setPointEncodings(new HashSet<>(ec.getPointEncodings()));
      }
      return option;
    } else if (rsa != null) {
      KeyParametersOption.RSAParametersOption option = new KeyParametersOption.RSAParametersOption();
      option.setModulusLengths(rsa.getModulus());
      return option;
    } else if (dsa != null) {
      KeyParametersOption.DSAParametersOption option = new KeyParametersOption.DSAParametersOption();
      option.setPlengths(dsa.getP());
      option.setQlengths(dsa.getQ());
      return option;
    } else {
      return KeyParametersOption.ALLOW_ALL;
    }
  } // method toXiKeyParametersOption

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
  } // method validateRanges

  @Override
  public void validate() throws InvalidConfException {
    validate(dsa, ec, rsa);
  } // method validate

}
