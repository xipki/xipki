// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.profile.id;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xipki.security.OIDs;
import org.xipki.util.codec.Args;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Lijun Liao (xipki)
 */
public class QCStatementID extends AbstractID {

  private static final Map<String, QCStatementID> typeMap = new HashMap<>();

  public static QCStatementID QCStatementV1 = initOf(
      OIDs.QCS.id_qcs_pkixQCSyntax_v1, "QCStatement1", "QCStatementV1");

  public static QCStatementID QCStatementV2 = initOf(
      OIDs.QCS.id_qcs_pkixQCSyntax_v2, "QCStatement2", "QCStatementV2");

  public static QCStatementID etsi_qcs_QcCompliance = initOf(
      OIDs.QCS.id_etsi_qcs_QcCompliance, "QcCompliance",
      "etsi-qcs-QcCompliance");

  public static QCStatementID etsi_qcs_QcLimitValue = initOf(
      OIDs.QCS.id_etsi_qcs_QcLimitValue, "QcLimitValue",
      "etsi-qcs-QcLimitValue");

  public static QCStatementID etsi_qcs_QcRetentionPeriod = initOf(
      OIDs.QCS.id_etsi_qcs_QcRetentionPeriod, "QcRetentionPeriod",
      "etsi-qcs-QcRetentionPeriod");

  public static QCStatementID etsi_qcs_QcSSCD = initOf(
      OIDs.QCS.id_etsi_qcs_QcSSCD, "QcSSCD", "etsi-qcs-QcSSCD");

  public static QCStatementID etsi_qcs_QcPDS = initOf(
      OIDs.QCS.id_etsi_qcs_QcPDS, "QcPDS", "etsi-qcs-QcPDS");

  public static QCStatementID etsi_qcs_QcType = initOf(
      OIDs.QCS.id_etsi_qcs_QcType, "QcType", "etsi-qcs-QcType");

  public static QCStatementID etsi_qcs_QcCClegislation = initOf(
      OIDs.QCS.id_etsi_qcs_QcCClegislation, "QcCClegislation",
      "etsi-qcs-QcCClegislation");

  public static QCStatementID etsi_psd2_qcStatement = initOf(
      OIDs.QCS.id_etsi_psd2_qcStatement, "psd2-qcStatement",
      "etsi-psd2-qcStatement");

  private QCStatementID(ASN1ObjectIdentifier oid, List<String> aliases) {
    super(oid, aliases);
  }

  private static QCStatementID initOf(
      ASN1ObjectIdentifier oid, String... aliases) {
    Args.notNull(oid, "oid");
    List<String> l = new ArrayList<>();
    if (aliases != null) {
      l.addAll(Arrays.asList(aliases));
    }
    l.add(oid.getId());
    return addToMap(new QCStatementID(oid, l), typeMap);
  }

  public static QCStatementID ofOid(ASN1ObjectIdentifier oid) {
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
      ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(c14n);
      return new QCStatementID(oid, Collections.singletonList(oid.getId()));
    } catch (RuntimeException e) {
      return null;
    }
  }

}
