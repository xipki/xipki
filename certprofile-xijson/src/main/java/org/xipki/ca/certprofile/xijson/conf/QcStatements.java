// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf;

import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableBinary;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ValidatableConf;
import org.xipki.util.exception.InvalidConfException;

import java.util.LinkedList;
import java.util.List;

/**
 * Extension QCStatements.
 *
 * @author Lijun Liao (xipki)
 */

public class QcStatements extends ValidatableConf {

  public static class Range2Type extends ValidatableConf {

    private int min;

    private int max;

    public int getMin() {
      return min;
    }

    public void setMin(int min) {
      this.min = min;
    }

    public int getMax() {
      return max;
    }

    public void setMax(int max) {
      this.max = max;
    }

    @Override
    public void validate() throws InvalidConfException {
    }

  } // method Range2Type

  public static class QcEuLimitValueType extends ValidatableConf {

    private String currency;

    private Range2Type amount;

    private Range2Type exponent;

    public String getCurrency() {
      return currency;
    }

    public void setCurrency(String currency) {
      this.currency = currency;
    }

    public Range2Type getAmount() {
      return amount;
    }

    public void setAmount(Range2Type amount) {
      this.amount = amount;
    }

    public Range2Type getExponent() {
      return exponent;
    }

    public void setExponent(Range2Type exponent) {
      this.exponent = exponent;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(currency, "currency");
      notNull(amount, "amount");
      notNull(exponent, "exponent");
      validate(amount, exponent);
    } // method validate

  } // class QcEuLimitValueType

  public static class PdsLocationType extends ValidatableConf {

    private String url;

    private String language;

    public String getUrl() {
      return url;
    }

    public void setUrl(String url) {
      this.url = url;
    }

    public String getLanguage() {
      return language;
    }

    public void setLanguage(String language) {
      this.language = language;
    }

    @Override
    public void validate() throws InvalidConfException {
      notBlank(url, "url");
      notBlank(language, "language");
    }

  } // class QcEuLimitValueType

  public static class QcStatementValueType extends ValidatableConf {

    private DescribableBinary constant;

    private Integer qcRetentionPeriod;

    private QcEuLimitValueType qcEuLimitValue;

    private List<PdsLocationType> pdsLocations;

    public DescribableBinary getConstant() {
      return constant;
    }

    public void setConstant(DescribableBinary constant) {
      this.constant = constant;
    }

    public Integer getQcRetentionPeriod() {
      return qcRetentionPeriod;
    }

    public void setQcRetentionPeriod(Integer qcRetentionPeriod) {
      this.qcRetentionPeriod = qcRetentionPeriod;
    }

    public QcEuLimitValueType getQcEuLimitValue() {
      return qcEuLimitValue;
    }

    public void setQcEuLimitValue(QcEuLimitValueType qcEuLimitValue) {
      this.qcEuLimitValue = qcEuLimitValue;
    }

    public List<PdsLocationType> getPdsLocations() {
      return pdsLocations;
    }

    public void setPdsLocations(List<PdsLocationType> pdsLocations) {
      this.pdsLocations = pdsLocations;
    }

    @Override
    public void validate() throws InvalidConfException {
      int num = 0;
      if (constant != null) {
        num++;
      }

      if (qcRetentionPeriod != null) {
        num++;
      }

      if (qcEuLimitValue != null) {
        num++;
      }

      if (CollectionUtil.isNotEmpty(pdsLocations)) {
        num++;
      }

      if (num != 1) {
        throw new InvalidConfException("Not exactly one of constant, qcRetentionPeriod, "
            + "qcEuLimitValue, pdsLocations is set");
      }

      validate(constant, qcEuLimitValue);
      validate(pdsLocations);
    } // method QcStatementValueType

  } // class QcStatementValueType

  public static class QcStatementType extends ValidatableConf {

    private DescribableOid statementId;

    private QcStatementValueType statementValue;

    public DescribableOid getStatementId() {
      return statementId;
    }

    public void setStatementId(DescribableOid statementId) {
      this.statementId = statementId;
    }

    public QcStatementValueType getStatementValue() {
      return statementValue;
    }

    public void setStatementValue(QcStatementValueType statementValue) {
      this.statementValue = statementValue;
    }

    @Override
    public void validate() throws InvalidConfException {
      notNull(statementId, "statementId");
      validate(statementId, statementValue);
    }

  }

  private List<QcStatementType> qcStatements;

  public List<QcStatementType> getQcStatements() {
    if (qcStatements == null) {
      qcStatements = new LinkedList<>();
    }
    return qcStatements;
  }

  public void setQcStatements(List<QcStatementType> qcStatements) {
    this.qcStatements = qcStatements;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(qcStatements, "qcStatements");
    validate(qcStatements);
  }

} // class QcStatements
