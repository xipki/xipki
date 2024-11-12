// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11.hsmproxy;

import java.util.HashMap;
import java.util.Map;

/**
 * The HSM proxy action enumeration.
 *
 * @author Lijun Liao (xipki)
 */

public enum ProxyAction {

  moduleCaps ("mcaps"),
  slotIds ("sids"),

  // mechanism infos
  mechInfos ("mis"),

  publicKeyByHandle ("pkbh"),

  keyByKeyId ("kbi"),
  keyByIdLabel ("kbil"),
  keyIdByIdLabel ("kibil"),

  objectExistsByIdLabel ("ebil"),

  destroyAllObjects ("dao"),
  destroyObjectsByHandle ("dobh"),
  destroyObjectsByIdLabel ("dobil"),

  genSecretKey ("gsk"),
  importSecretKey ("isk"),

  genRSAKeypair ("grsa"),
  genRSAKeypairOtf ("grsao"),
  // genDSAKeypairByKeysize
  genDSAKeypair2 ("gdsa2"),
  genDSAKeypair ("gdsa"),
  genDSAKeypairOtf ("gdsao"),
  genECKeypair ("gec"),
  genECKeypairOtf ("geco"),
  genSM2Keypair ("gsm2"),
  genSM2KeypairOtf ("gsm2o"),
  showDetails ("d"),
  sign ("s"),
  digestSecretKey ("dsk");

  private final String alias;

  private static final Map<String, ProxyAction> namealiasActionMap = new HashMap<>();

  static {
    for (ProxyAction p : ProxyAction.values()) {
      namealiasActionMap.put(p.name().toLowerCase(), p);
    }

    for (ProxyAction p : ProxyAction.values()) {
      String lc = p.alias.toLowerCase();
      if (namealiasActionMap.containsKey(lc)) {
        throw new IllegalStateException("invalid alias " + p.alias);
      }
      namealiasActionMap.put(lc, p);
    }
  }

  ProxyAction(String alias) {
    this.alias = alias;
  }

  public String getAlias() {
    return alias;
  }

  public static ProxyAction ofNameIgnoreCase(String name) {
    return namealiasActionMap.get(name.toLowerCase());
  }

}
