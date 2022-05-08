/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.security.util;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.DSAParameterGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.DSAParameterSpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Cache for DSA parameter specs.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
public final class DSAParameterCache {
  private static final Logger LOG = LoggerFactory.getLogger(DSAParameterCache.class);

  private static final Map<String, DSAParameterSpec> cache = new HashMap<>();

  static {
    String resourceFile = "/conf/DSAParameters.cfg";
    InputStream confStream = DSAParameterCache.class.getResourceAsStream(resourceFile);
    BufferedReader reader =
        new BufferedReader(new InputStreamReader(confStream, StandardCharsets.UTF_8));

    String line;
    try {
      while ((line = reader.readLine()) != null) {
        line = line.trim();
        if (line.isEmpty() || line.startsWith("#")) {
          continue;
        }

        if (!line.startsWith("DSA/")) {
          continue;
        }

        String[] tokens = line.split("/");
        int plen = Integer.parseInt(tokens[1]);
        int qlen = Integer.parseInt(tokens[2]);

        String line0 = reader.readLine().trim();
        if (!line0.startsWith("P:")) {
          continue;
        }
        BigInteger p = new BigInteger(line0.substring(2).trim(), 16);

        line0 = reader.readLine().trim();
        if (!line0.startsWith("Q:")) {
          continue;
        }
        BigInteger q = new BigInteger(line0.substring(2).trim(), 16);

        line0 = reader.readLine().trim();
        if (!line0.startsWith("G:")) {
          continue;
        }
        BigInteger g = new BigInteger(line0.substring(2).trim(), 16);

        addDSAParamSpec(plen, qlen, p, q, g);
      }
    } catch (Exception ex) {
      LOG.error("error reading DSAParameters", ex);
    } finally {
      try {
        reader.close();
      } catch (IOException ex) {
      }
    }
  }

  private DSAParameterCache() {
  }

  private static void addDSAParamSpec(
      int plen, int qlen, BigInteger p, BigInteger q, BigInteger g) {
    DSAParameterSpec spec = new DSAParameterSpec(p, q, g);

    boolean match = true;
    if (plen != p.bitLength()) {
      match = false;
      LOG.error("plen and P does not match");
    }
    if (plen != p.bitLength()) {
      match = false;
      LOG.error("plen and P does not match");
    }

    if (match) {
      cache.put(plen + "-" + qlen, spec);
      LOG.info("added DSA parameter for {} bit P and {} bit Q", plen, qlen);
    }
  }

  public static DSAParameterSpec getDSAParameterSpec(int plength, int qlength,
      SecureRandom random) {
    DSAParameterSpec spec = cache.get(plength + "-" + qlength);
    if (spec != null) {
      return new DSAParameterSpec(spec.getP(), spec.getQ(), spec.getG());
    }

    return getNewDSAParameterSpec(plength, qlength, random);
  }

  public static DSAParameterSpec getNewDSAParameterSpec(int plength, int qlength,
      SecureRandom random) {
    final int certainty = 80;
    SecureRandom tmpRandom = (random == null) ? new SecureRandom() : random;
    DSAParametersGenerator paramGen = new DSAParametersGenerator(new SHA512Digest());
    DSAParameterGenerationParameters genParams =
        new DSAParameterGenerationParameters(plength, qlength, certainty, tmpRandom);
    paramGen.init(genParams);
    DSAParameters dsaParams = paramGen.generateParameters();
    return new DSAParameterSpec(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
  }

}
