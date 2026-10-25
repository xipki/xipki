// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.id;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.oid.QCStatementOIDs;
import org.xipki.codec.util.Args;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * QCStatement ID.
 *
 * @author Lijun Liao (xipki)
 */
public class QCStatementID extends AbstractID {

  private static final Map<String, QCStatementID> typeMap = new HashMap<>();

  public static final QCStatementID QCStatementV1 = initOf(
      QCStatementOIDs.id_qcs_pkixQCSyntax_v1, "QCStatement1", "QCStatementV1");

  public static final QCStatementID QCStatementV2 = initOf(
      QCStatementOIDs.id_qcs_pkixQCSyntax_v2, "QCStatement2", "QCStatementV2");

  public static final QCStatementID etsi_qcs_QcCompliance = initOf(
      QCStatementOIDs.id_etsi_qcs_QcCompliance, "QcCompliance", "etsi-qcs-QcCompliance");

  public static final QCStatementID etsi_qcs_QcLimitValue = initOf(
      QCStatementOIDs.id_etsi_qcs_QcLimitValue, "QcLimitValue", "etsi-qcs-QcLimitValue");

  public static final QCStatementID etsi_qcs_QcRetentionPeriod = initOf(
      QCStatementOIDs.id_etsi_qcs_QcRetentionPeriod,
      "QcRetentionPeriod", "etsi-qcs-QcRetentionPeriod");

  public static final QCStatementID etsi_qcs_QcSSCD = initOf(
      QCStatementOIDs.id_etsi_qcs_QcSSCD, "QcSSCD", "etsi-qcs-QcSSCD");

  public static final QCStatementID etsi_qcs_QcPDS = initOf(
      QCStatementOIDs.id_etsi_qcs_QcPDS, "QcPDS", "etsi-qcs-QcPDS");

  public static final QCStatementID etsi_qcs_QcType = initOf(
      QCStatementOIDs.id_etsi_qcs_QcType, "QcType", "etsi-qcs-QcType");

  public static final QCStatementID etsi_qcs_QcCClegislation = initOf(
      QCStatementOIDs.id_etsi_qcs_QcCClegislation, "QcCClegislation", "etsi-qcs-QcCClegislation");

  public static final QCStatementID etsi_psd2_qcStatement = initOf(
      QCStatementOIDs.id_etsi_psd2_qcStatement, "psd2-qcStatement", "etsi-psd2-qcStatement");

  private QCStatementID(Asn1Oid oid, List<String> aliases) {
    super(oid, aliases);
  }

  private static QCStatementID initOf(Asn1Oid oid, String... aliases) {
    Args.notNull(oid, "oid");
    List<String> l = new ArrayList<>();
    if (aliases != null) {
      l.addAll(Arrays.asList(aliases));
    }
    l.add(oid.getId());
    return addToMap(new QCStatementID(oid, l), typeMap);
  }

  public static QCStatementID ofOid(Asn1Oid oid) {
    Args.notNull(oid, "oid");
    QCStatementID attr = ofOidOrName(typeMap, oid.getId());
    if (attr != null) {
      return attr;
    }

    return new QCStatementID(oid, Collections.singletonList(oid.getId()));
  }

  public static QCStatementID ofOidOrName(String oidOrName) {
    String c14n = canonicalizeAlias(Args.notNull(oidOrName, "oidOrName"));
    QCStatementID id = ofOidOrName(typeMap, c14n);
    if (id != null) {
      return id;
    }

    try {
      Asn1Oid oid = new Asn1Oid(c14n);
      return new QCStatementID(oid, Collections.singletonList(oid.getId()));
    } catch (RuntimeException e) {
      return null;
    }
  }

}
