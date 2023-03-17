// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.api;

import java.io.Closeable;

/**
 * OCSP server interface.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public interface OcspServer extends Closeable {

  ResponderAndPath getResponderForPath(String path);

  OcspRespWithCacheInfo answer(Responder responder, byte[] request, boolean viaGet);

  boolean healthCheck(Responder responder);
}
