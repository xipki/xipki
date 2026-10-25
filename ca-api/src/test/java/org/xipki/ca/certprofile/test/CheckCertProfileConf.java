// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.test;

import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.conf.XijsonCertprofileType;

import java.io.File;

/**
 * Test whether the certificate profile file can be parsed.
 *
 * @author Lijun Liao (xipki)
 */
public class CheckCertProfileConf {

  public static void main(String[] args) {
    try {
      String dir = "assemblies/xipki-qa/" +
          "src/assembly/unfiltered/xipki-qa-cli/qa/certprofile/";
      String fileName = "certprofile-caliptra.json";
      XijsonCertprofileType type = XijsonCertprofileType.parse(new File(dir + fileName));
      XijsonCertprofile conf = new XijsonCertprofile();
      conf.initialize(type);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

}
