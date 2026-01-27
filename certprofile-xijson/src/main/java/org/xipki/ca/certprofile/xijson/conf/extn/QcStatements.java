// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson.conf.extn;

import org.xipki.ca.api.profile.id.QCStatementID;
import org.xipki.ca.certprofile.xijson.conf.ConstantExtnValue;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonEncodable;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.CollectionUtil;

import java.util.ArrayList;
import java.util.List;

/**
 * Extension QCStatements.
 *
 * @author Lijun Liao (xipki)
 */

public class QcStatements implements JsonEncodable {

  private final List<QcStatementType> qcStatements;

  public QcStatements(List<QcStatementType> qcStatements) {
    this.qcStatements = Args.notEmpty(qcStatements, "qcStatements");
  }

  public List<QcStatementType> getQcStatements() {
    return qcStatements;
  }

  @Override
  public JsonMap toCodec() {
    return new JsonMap().putEncodables("qcStatements", qcStatements);
  }

  public static QcStatements parse(JsonMap json) throws CodecException {
    JsonList list = json.getNnList("qcStatements");
    List<QcStatementType> qcStatements = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      qcStatements.add(QcStatementType.parse(v));
    }
    return new QcStatements(qcStatements);
  }

  public static class Range2Type implements JsonEncodable {

    private final int min;

    private final int max;

    public Range2Type(int min, int max) {
      this.min = min;
      this.max = Args.min(max, "max", min);
    }

    public int getMin() {
      return min;
    }

    public int getMax() {
      return max;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("min", min).put("max", max);
    }

    public static Range2Type parse(JsonMap json) throws CodecException {
      return new Range2Type(json.getNnInt("min"),
          json.getNnInt("max"));
    }

  } // method Range2Type

  public static class QcStatementValueType implements JsonEncodable {

    private final ConstantExtnValue constant;

    private final Integer qcRetentionPeriod;

    private final QcEuLimitValueType qcEuLimitValue;

    private final List<PdsLocationType> pdsLocations;

    public QcStatementValueType(
        ConstantExtnValue constant, Integer qcRetentionPeriod,
        QcEuLimitValueType qcEuLimitValue, List<PdsLocationType> pdsLocations) {
      int num = 0;
      if (constant != null) num++;

      if (qcRetentionPeriod != null) num++;

      if (qcEuLimitValue != null) num++;

      if (CollectionUtil.isNotEmpty(pdsLocations)) num++;

      if (num != 1) {
        throw new IllegalArgumentException("Not exactly one of constant, " +
            "qcRetentionPeriod, qcEuLimitValue, pdsLocations is set");
      }

      this.constant = constant;
      this.qcRetentionPeriod = qcRetentionPeriod;
      this.qcEuLimitValue = qcEuLimitValue;
      this.pdsLocations = pdsLocations;
    }

    public ConstantExtnValue getConstant() {
      return constant;
    }

    public Integer getQcRetentionPeriod() {
      return qcRetentionPeriod;
    }

    public QcEuLimitValueType getQcEuLimitValue() {
      return qcEuLimitValue;
    }

    public List<PdsLocationType> getPdsLocations() {
      return pdsLocations;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap()
          .put("constant", constant)
          .put("qcRetentionPeriod", qcRetentionPeriod)
          .put("qcEuLimitValue", qcEuLimitValue)
          .putEncodables("pdsLocations", pdsLocations);
    }

    public static QcStatementValueType parse(JsonMap json)
        throws CodecException {
      JsonMap map = json.getMap("constant");
      ConstantExtnValue constant = (map == null) ? null
          : ConstantExtnValue.parse(map);

      map = json.getMap("qcEuLimitValue");
      QcEuLimitValueType qcEuLimitValue = (map == null) ? null
          : QcEuLimitValueType.parse(map);

      JsonList list = json.getList("pdsLocations");
      List<PdsLocationType> pdsLocations = null;
      if (list != null) {
        pdsLocations = new ArrayList<>(list.size());
        for (JsonMap v : list.toMapList()) {
          pdsLocations.add(PdsLocationType.parse(v));
        }
      }
      return new QcStatementValueType(constant,
          json.getInt("qcRetentionPeriod"),
          qcEuLimitValue, pdsLocations);
    }

  } // class QcStatementValueType

  public static class QcStatementType implements JsonEncodable {

    private final QCStatementID statementId;

    private final QcStatementValueType statementValue;

    public QcStatementType(QCStatementID statementId,
                           QcStatementValueType statementValue) {
      this.statementId = Args.notNull(statementId, "statementId");
      this.statementValue = statementValue;
    }

    public QCStatementID getStatementId() {
      return statementId;
    }

    public QcStatementValueType getStatementValue() {
      return statementValue;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap()
          .put("statementId", statementId.getMainAlias())
          .put("statementValue", statementValue);
    }

    public static QcStatementType parse(JsonMap json) throws CodecException {
      JsonMap map = json.getMap("statementValue");
      QcStatementValueType statementValue = (map == null) ? null
          : QcStatementValueType.parse(map);
      return new QcStatementType(
          QCStatementID.ofOidOrName(json.getNnString("statementId")),
          statementValue);
    }

  }

  public static class PdsLocationType implements JsonEncodable {

    private final String url;

    private final String language;

    public PdsLocationType(String url, String language) {
      this.url = Args.notBlank(url, "url");
      this.language = Args.notBlank(language, "language");
    }

    public String getUrl() {
      return url;
    }

    public String getLanguage() {
      return language;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("url", url)
          .put("language", language);
    }

    public static PdsLocationType parse(JsonMap json)
        throws CodecException {
      return new PdsLocationType(json.getNnString("url"),
          json.getNnString("language"));
    }

  } // class QcEuLimitValueType

  public static class QcEuLimitValueType implements JsonEncodable {

    private final String currency;

    private final Range2Type amount;

    private final Range2Type exponent;

    public QcEuLimitValueType(String currency, Range2Type amount,
                              Range2Type exponent) {
      this.currency = Args.notBlank(currency, "currency");
      this.amount   = Args.notNull(amount, "amount");
      this.exponent = Args.notNull(exponent, "exponent");
    }

    public String getCurrency() {
      return currency;
    }

    public Range2Type getAmount() {
      return amount;
    }

    public Range2Type getExponent() {
      return exponent;
    }

    @Override
    public JsonMap toCodec() {
      return new JsonMap().put("currency", currency)
          .put("amount", amount).put("exponent", exponent);
    }

    public static QcEuLimitValueType parse(JsonMap json)
        throws CodecException {
      return new QcEuLimitValueType(json.getNnString("currency"),
          Range2Type.parse(json.getNnMap("amount")),
          Range2Type.parse(json.getNnMap("exponent")));
    }

  } // class QcEuLimitValueType

} // class QcStatements
