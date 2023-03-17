// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.api.mgmt;

/**
 * OCSP server management message.
 *
 * @author Lijun Liao
 */

public abstract class MgmtMessage {

  public enum MgmtAction {

    restartServer;

    public static MgmtAction ofName(String str) {
      for (MgmtAction action : MgmtAction.values()) {
        if (action.name().equalsIgnoreCase(str)) {
          return action;
        }
      }

      return null;
    }

  }

}
