// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0
package org.xipki.pkcs11.xihsm.objects;

import org.xipki.pkcs11.xihsm.attr.XiTemplate;

/**
 * @author Lijun Liao (xipki)
 */
public interface XiPublicOrSecretKey {

  XiTemplate getWrapTemplate();

  boolean isTrusted();

}
