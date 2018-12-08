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

package org.xipki.ca.mgmt.msg;

/**
 * TODO.
 * @author Lijun Liao
 */

public enum MgmtAction {

  addCa,
  addCaAlias,
  addCertprofile,
  addCertprofileToCa,
  addPublisher,
  addPublisherToCa,
  addRequestor,
  addRequestorToCa,
  addSigner,
  addUser,
  addUserToCa,
  changeCa,
  changeCertprofile,
  changePublisher,
  changeRequestor,
  changeSigner,
  changeUser,
  clearPublishQueue,
  exportConf,
  generateCertificate,
  generateCrlOnDemand,
  generateRootCa,
  getAliasesForCa,
  getCa,
  getCaAliasNames,
  getCaHasUsersForUser,
  getCaNameForAlias,
  getCaNames,
  getCaSystemStatus,
  getCert,
  getCertprofile,
  getCertprofileNames,
  getCertprofilesForCa,
  getCertRequest,
  getCrl,
  getCurrentCrl,
  getFailedCaNames,
  getInactiveCaNames,
  getPublisher,
  getPublisherNames,
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
  getUser,
  listCertificates,
  loadConf,
  notifyCaChange,
  refreshTokenForSignerType,
  removeCa,
  removeCaAlias,
  removeCertificate,
  removeCertprofile,
  removeCertprofileFromCa,
  removePublisher,
  removePublisherFromCa,
  removeRequestor,
  removeRequestorFromCa,
  removeSigner,
  removeUser,
  removeUserFromCa,
  republishCertificates,
  restartCaSystem,
  revokeCa,
  revokeCertficate,
  unlockCa,
  unrevokeCa,
  unrevokeCertificate;

  public static final MgmtAction ofName(String str) {
    for (MgmtAction action : MgmtAction.values()) {
      if (action.name().equalsIgnoreCase(str)) {
        return action;
      }
    }

    return null;
  }

}
