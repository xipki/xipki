// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

/**
 * Mgmt Action enumeration.
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
  getCertStatistics,
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
  getRequestor,
  getRequestorNames,
  getRequestorsForCa,
  getSigner,
  getSignerNames,
  getSimpleCertprofileInfo,
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
  revokeCertificate,
  tokenInfoP11,
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
