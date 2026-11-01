// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns;

import java.io.IOException;

/**
 * Sends one query of class IN and returns the matching response.
 *
 * @author Lijun Liao (xipki)
 */
public interface DnsTransport {

  /**
   * Sends the query and returns the response. The response has the same ID and
   * question as the query.
   *
   * @param qname the name to query.
   * @param qtype the type to query.
   * @return the response, with any rcode.
   * @throws IOException if no response was received.
   */
  DnsMessage query(DnsName qname, int qtype) throws IOException;

}
