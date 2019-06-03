/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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

import java.util.List;

import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableBinary;
import org.xipki.ca.certprofile.xijson.conf.Describable.DescribableOid;
import org.xipki.util.CollectionUtil;
import org.xipki.util.InvalidConfException;
import org.xipki.util.ValidatableConf;

import com.alibaba.fastjson.annotation.JSONField;

/**
 * Configuration of the extension QCStatements.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class QcStatementType extends ValidatableConf {

  @JSONField(ordinal = 1)
  private DescribableOid statementId;

  @JSONField(ordinal = 2)
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
    validate(statementId);
    validate(statementValue);
  }

  public static class Range2Type extends ValidatableConf {

    @JSONField(ordinal = 1)
    private int min;

    @JSONField(ordinal = 2)
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

  }

  public static class QcEuLimitValueType extends ValidatableConf {

    @JSONField(ordinal = 1)
    private String currency;

    @JSONField(ordinal = 2)
    private Range2Type amount;

    @JSONField(ordinal = 3)
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
      notEmpty(currency, "currency");
      notNull(amount, "amount");
      validate(amount);
      notNull(exponent, "exponent");
      validate(exponent);
    }

  }

  public static class PdsLocationType extends ValidatableConf {

    @JSONField(ordinal = 1)
    private String url;

    @JSONField(ordinal = 2)
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
      notEmpty(url, "url");
      notEmpty(language, "language");
    }

  }

  public static class QcStatementValueType extends ValidatableConf {

    @JSONField(ordinal = 1)
    private DescribableBinary constant;

    @JSONField(ordinal = 1)
    private Integer qcRetentionPeriod;

    @JSONField(ordinal = 1)
    private QcEuLimitValueType qcEuLimitValue;

    @JSONField(ordinal = 1)
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

      validate(constant);
      validate(qcEuLimitValue);
      validate(pdsLocations);
    }

  }

}
