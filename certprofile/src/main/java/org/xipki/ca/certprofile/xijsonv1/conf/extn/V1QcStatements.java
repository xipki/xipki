// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijsonv1.conf.extn;

import org.xipki.ca.api.profile.id.QCStatementID;
import org.xipki.ca.certprofile.xijson.conf.ConstantExtnValue;
import org.xipki.ca.certprofile.xijson.conf.ExtensionValueConf;
import org.xipki.ca.certprofile.xijson.conf.ExtensionValueConf.QcStatements;
import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableBinary;
import org.xipki.ca.certprofile.xijsonv1.conf.type.DescribableOid;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonList;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.extra.misc.CollectionUtil;

import java.util.ArrayList;
import java.util.List;

/**
 * V1 QC Statements.
 *
 * @author Lijun Liao (xipki)
 */

public class V1QcStatements {

  private final List<QcStatementType> qcStatements;

  private V1QcStatements(List<QcStatementType> qcStatements) {
    this.qcStatements = Args.notEmpty(qcStatements, "qcStatements");
  }

  public QcStatements toV2() {
    List<ExtensionValueConf.QcStatementType> list = new ArrayList<>(qcStatements.size());

    for (QcStatementType t : qcStatements) {
      list.add(t.toV2());
    }

    return new QcStatements(list.isEmpty() ? null : list);
  }

  public static V1QcStatements parse(JsonMap json) throws CodecException {
    JsonList list = json.getNnList("qcStatements");
    List<QcStatementType> qcStatements = new ArrayList<>(list.size());
    for (JsonMap v : list.toMapList()) {
      qcStatements.add(QcStatementType.parse(v));
    }
    return new V1QcStatements(qcStatements);
  }

  private static class QcStatementType {

    private final DescribableOid statementId;

    private final QcStatementValueType statementValue;

    public QcStatementType(DescribableOid statementId, QcStatementValueType statementValue) {
      this.statementId = Args.notNull(statementId, "statementId");
      this.statementValue = statementValue;
    }

    public ExtensionValueConf.QcStatementType toV2() {
      return new ExtensionValueConf.QcStatementType( QCStatementID.ofOid(statementId.oid()),
          (statementValue == null) ? null : statementValue.toV2());
    }

    public static QcStatementType parse(JsonMap json) throws CodecException {
      JsonMap map = json.getMap("statementValue");
      QcStatementValueType statementValue = (map == null) ? null
          : QcStatementValueType.parse(map);
      return new QcStatementType(DescribableOid.parseNn(json, "statementId"), statementValue);
    }

  }

  private static class QcStatementValueType {

    private final DescribableBinary constant;

    private final Integer qcRetentionPeriod;

    private final ExtensionValueConf.QcEuLimitValueType qcEuLimitValue;

    private final List<ExtensionValueConf.PdsLocationType> pdsLocations;

    private QcStatementValueType( DescribableBinary constant, Integer qcRetentionPeriod,
        ExtensionValueConf.QcEuLimitValueType qcEuLimitValue,
        List<ExtensionValueConf.PdsLocationType> pdsLocations) {
      this.constant = constant;
      this.qcRetentionPeriod = qcRetentionPeriod;
      this.qcEuLimitValue = qcEuLimitValue;
      this.pdsLocations = pdsLocations;

      int num =    (constant == null ? 0 : 1) + (qcRetentionPeriod == null ? 0 : 1) +
          (qcEuLimitValue    == null ? 0 : 1);

      if (CollectionUtil.isNotEmpty(pdsLocations)) {
        num++;
      }

      if (num != 1) {
        throw new IllegalArgumentException("Not exactly one of constant, " +
            "qcRetentionPeriod, qcEuLimitValue, pdsLocations is set");
      }
    } // method QcStatementValueType

    public ExtensionValueConf.QcStatementValueType toV2() {
      ConstantExtnValue v2Constant = null;
      if (constant != null) {
        v2Constant = new ConstantExtnValue(null, constant.value());
      }

      return new ExtensionValueConf.QcStatementValueType(v2Constant,
          qcRetentionPeriod, qcEuLimitValue, pdsLocations);
    }

    public static QcStatementValueType parse(JsonMap json)
        throws CodecException {
      DescribableBinary constant = DescribableBinary.parse(json, "constant");

      JsonMap map = json.getMap("qcEuLimitValue");
      ExtensionValueConf.QcEuLimitValueType qcEuLimitValue = (map == null) ? null
          : ExtensionValueConf.QcEuLimitValueType.parse(map);

      JsonList list = json.getList("pdsLocations");
      List<ExtensionValueConf.PdsLocationType> pdsLocations = null;
      if (list != null) {
        pdsLocations = new ArrayList<>(list.size());
        for (JsonMap v:  list.toMapList()) {
          pdsLocations.add(ExtensionValueConf.PdsLocationType.parse(v));
        }
      }

      return new QcStatementValueType(constant,
          json.getInt("qcRetentionPeriod"), qcEuLimitValue, pdsLocations);
    }
  }

}
