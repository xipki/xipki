// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

/**
 * CA Management action enums.
 *
 * @author Lijun Liao (xipki)
 */

public enum MgmtAction {

  addCa,
  addCaAlias,
  addCertprofile,
  addCertprofileToCa,
  addDbSchema,
  addKeypairGen,
  addPublisher,
  addPublisherToCa,
  addRequestor,
  addRequestorToCa,
  addSigner,
  changeCa,
  changeCertprofile,
  changeDbSchema,
  changeKeypairGen,
  changePublisher,
  changeRequestor,
  changeSigner,
  exportConf,
  generateCertificate,
  generateKeyCert,
  generateCrossCertificate,
  generateCrlOnDemand,
  generateRootCa,
  getAliasesForCa,
  getCa,
  getCaAliasNames,
  getCaCerts,
  getCaNameForAlias,
  getCaNames,
  getCaSystemStatus,
  getCert,
  getCertprofile,
  getCertprofileNames,
  getCertprofilesForCa,
  getCrl,
  getCurrentCrl,
  getDbSchemas,
  getFailedCaNames,
  getInactiveCaNames,
  getKeypairGen,
  getKeypairGenNames,
  getPublisher,
  getPublisherNames,
  getPublisherNamesForCa,
  @Deprecated
  getPublishersForCa,
  getRequestor,
  getRequestorNames,
  getRequestorsForCa,
  getSigner,
  getSignerNames,
  getSuccessfulCaNames,
  getSupportedCertprofileTypes,
  getSupportedPublisherTypes,
  getSupportedSignerTypes,
  listCertificates,
  loadConf,
  notifyCaChange,
  removeCa,
  removeCaAlias,
  removeCertificate,
  removeCertprofile,
  removeCertprofileFromCa,
  removeDbSchema,
  removeKeypairGen,
  removePublisher,
  removePublisherFromCa,
  removeRequestor,
  removeRequestorFromCa,
  removeSigner,
  republishCertificates,
  restartCa,
  restartCaSystem,
  revokeCa,
  @Deprecated
  revokeCertficate,
  revokeCertificate,
  unlockCa,
  unrevokeCa,
  unsuspendCertificate;

  public static MgmtAction ofName(String str) {
    for (MgmtAction action : MgmtAction.values()) {
      if (action.name().equalsIgnoreCase(str)) {
        return action;
      }
    }

    return null;
  }

} // class MgmtAction
