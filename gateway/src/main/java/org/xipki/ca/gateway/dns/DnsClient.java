// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.dns;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.gateway.dns.dnssec.DnssecValidator;
import org.xipki.ca.gateway.dns.dnssec.ValidationBudget;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Looks up TXT and address records, following CNAMEs, with optional DNSSEC validation.
 *
 * @author Lijun Liao (xipki)
 */
public class DnsClient {

  private static final Logger LOG = LoggerFactory.getLogger(DnsClient.class);

  public static final int MAX_CNAME_DEPTH = 8;

  private final DnsTransport transport;

  private final DnssecValidator validator;

  /**
   * Constructor.
   *
   * @param transport the transport.
   * @param validator the DNSSEC validator, or {@code null} to accept unsigned answers.
   */
  public DnsClient(DnsTransport transport, DnssecValidator validator) {
    this.transport = transport;
    this.validator = validator;
  }

  /**
   * Returns the TXT records of the name. Each element is the concatenation of the
   * character-strings of one TXT record.
   *
   * @param name the name.
   * @return the TXT records, empty if the name or the records do not exist.
   * @throws IOException if the query failed, or the answer is not DNSSEC-validated
   *         while validation is required ({@link DnsException#reason()} is set).
   */
  public List<String> queryTxt(String name) throws IOException {
    List<DnsRecord> rrset = lookup(DnsName.of(name), DnsRecord.TYPE_TXT);
    List<String> ret = new ArrayList<>(rrset.size());
    for (DnsRecord rr : rrset) {
      ret.add(rr.txt());
    }
    return ret;
  }

  /**
   * Returns the IPv4 (A) and IPv6 (AAAA) addresses of the host. If one of both queries
   * fails, the addresses of the other one are returned; a DNSSEC validation failure is
   * always thrown.
   *
   * @param host the host name.
   * @return the addresses, empty if the host has none.
   * @throws IOException if both queries failed, or the DNSSEC validation failed.
   */
  public List<InetAddress> queryAddresses(String host) throws IOException {
    DnsName name = DnsName.of(host);
    List<InetAddress> ret = new ArrayList<>(2);
    IOException error = null;
    for (int type : new int[]{DnsRecord.TYPE_A, DnsRecord.TYPE_AAAA}) {
      try {
        int len = type == DnsRecord.TYPE_A ? 4 : 16;
        for (DnsRecord rr : lookup(name, type)) {
          if (rr.rdata().length != len) {
            throw new DnsException("invalid RDATA length of " + rr);
          }
          ret.add(InetAddress.getByAddress(host, rr.rdata()));
        }
      } catch (IOException ex) {
        if (ex instanceof DnsException && ((DnsException) ex).reason() != null) {
          throw ex;
        }
        LOG.debug("query {}/{} failed: {}", name, type, ex.getMessage());
        error = (error == null) ? ex : error;
      }
    }

    if (ret.isEmpty() && error != null) {
      throw error;
    }
    return ret;
  }

  /**
   * Returns the RRset of the given type, following CNAMEs up to a depth of 8.
   */
  private List<DnsRecord> lookup(DnsName name, int type) throws IOException {
    DnsName qname = name;
    ValidationBudget budget = validator == null ? null : new ValidationBudget();
    Set<DnsName> visited = new HashSet<>();

    for (int depth = 0; depth <= MAX_CNAME_DEPTH; depth++) {
      if (!visited.add(qname)) {
        throw new DnsException("CNAME loop at " + qname);
      }

      if (budget != null) {
        budget.countQuery();
      }

      DnsMessage response = transport.query(qname, type);
      int rcode = response.rcode();
      if (rcode == DnsMessage.RCODE_NXDOMAIN) {
        LOG.debug("{}/{}: NXDOMAIN", qname, type);
        return Collections.emptyList();
      } else if (rcode != DnsMessage.RCODE_NOERROR) {
        String ede = response.edeCode() == -1 ? ""
            : " (EDE " + response.edeCode() + ": " + response.edeText() + ")";
        throw new DnsException("query " + qname + "/" + type + " returned "
            + DnsMessage.rcodeText(rcode) + ede);
      }

      if (validator != null && hasDname(response, qname)) {
        // a CNAME synthesized from a DNAME is not signed
        throw new DnsException(DnsException.Reason.DNAME,
            "DNAME redirection of " + qname + " is not supported");
      }

      List<DnsRecord> rrset = response.answer(qname, type);
      if (!rrset.isEmpty()) {
        validate(response, qname, type, rrset, budget);
        return rrset;
      }

      List<DnsRecord> cnames = response.answer(qname, DnsRecord.TYPE_CNAME);
      if (cnames.isEmpty()) {
        return Collections.emptyList();
      }

      if (cnames.size() > 1) {
        throw new DnsException("more than one CNAME for " + qname);
      }

      validate(response, qname, DnsRecord.TYPE_CNAME, cnames, budget);
      DnsName target = cnames.get(0).cnameTarget();
      LOG.debug("following CNAME {} -> {}", qname, target);
      qname = target;
    }

    throw new DnsException("too many CNAMEs for " + name);
  }

  private void validate(DnsMessage response, DnsName owner, int type, List<DnsRecord> rrset,
                        ValidationBudget budget) throws DnsException {
    if (validator != null) {
      validator.validate(owner, type, rrset, response.rrsigs(owner, type), budget);
    }
  }

  private static boolean hasDname(DnsMessage response, DnsName name) {
    for (DnsRecord rr : response.answer()) {
      if (rr.type() == DnsRecord.TYPE_DNAME && name.isProperSubdomainOf(rr.name())) {
        return true;
      }
    }
    return false;
  }

}
