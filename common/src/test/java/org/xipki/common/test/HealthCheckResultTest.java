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

package org.xipki.common.test;

import org.junit.Test;
import org.xipki.common.HealthCheckResult;

import junit.framework.Assert;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class HealthCheckResultTest {

  @Test
  public void test1() {
    String encoded = "{\"healthy\":true}";
    HealthCheckResult result = HealthCheckResult.getInstanceFromJsonMessage("default", encoded);

    String noPrettyJson = "{\"healthy\":true}";

    String prettyJson = "{\n"
        + "    \"healthy\":true\n"
        + "}";
    check(result, noPrettyJson, prettyJson);
  }

  @Test
  public void test2() {
    String encoded = "{\"healthy\":true,\"checks\":{\"childcheck\":{\"healthy\":false,"
        + "\"checks\":{\"childChildCheck\":{\"healthy\":false}}},"
        + "\"childcheck2\":{\"healthy\":false}}}";

    HealthCheckResult result = HealthCheckResult.getInstanceFromJsonMessage("default",
        encoded);

    String noPrettyJson = "{\"healthy\":true,\"checks\":{\"childcheck\":{\"healthy\":false,"
        + "\"checks\":{\"childChildCheck\":{\"healthy\":false}}},"
        + "\"childcheck2\":{\"healthy\":false}}}";

    String prettyJson = "{\n"
        + "    \"healthy\":true,\n"
        + "    \"checks\":{\n"
        + "        \"childcheck\":{\n"
        + "            \"healthy\":false,\n"
        + "            \"checks\":{\n"
        + "                \"childChildCheck\":{\n"
        + "                    \"healthy\":false\n"
        + "                }\n"
        + "            }\n"
        + "        },\n"
        + "        \"childcheck2\":{\n"
        + "            \"healthy\":false\n"
        + "        }\n"
        + "    }\n"
        + "}";

    check(result, noPrettyJson, prettyJson);
  }

  @Test
  public void test3() {
    HealthCheckResult result = new HealthCheckResult("mycheck-negative");
    result.setHealthy(false);

    String noPrettyJson = "{\"healthy\":false}";

    String prettyJson = "{\n"
        + "    \"healthy\":false\n"
        + "}";
    check(result, noPrettyJson, prettyJson);
  }

  @Test
  public void test4() {
    HealthCheckResult result = new HealthCheckResult("mycheck-positive");
    result.setHealthy(true);

    String noPrettyJson = "{\"healthy\":true}";

    String prettyJson = "{\n"
        + "    \"healthy\":true\n"
        + "}";
    check(result, noPrettyJson, prettyJson);
  }

  @Test
  public void test5() {
    HealthCheckResult result = new HealthCheckResult("mycheck-positive");
    result.setHealthy(true);

    HealthCheckResult childCheck = new HealthCheckResult("childcheck");
    result.addChildCheck(childCheck);
    childCheck.setHealthy(false);

    HealthCheckResult childCheck2 = new HealthCheckResult("childcheck2");
    result.addChildCheck(childCheck2);
    childCheck.setHealthy(false);

    HealthCheckResult childChildCheck = new HealthCheckResult("childChildCheck");
    childCheck.addChildCheck(childChildCheck);
    childChildCheck.setHealthy(false);

    String noPrettyJson = "{\"healthy\":true,\"checks\":{\"childcheck\":{\"healthy\":false,"
        + "\"checks\":{\"childChildCheck\":{\"healthy\":false}}},\"childcheck2\":"
        + "{\"healthy\":false}}}";

    String prettyJson = "{\n"
        + "    \"healthy\":true,\n"
        + "    \"checks\":{\n"
        + "        \"childcheck\":{\n"
        + "            \"healthy\":false,\n"
        + "            \"checks\":{\n"
        + "                \"childChildCheck\":{\n"
        + "                    \"healthy\":false\n"
        + "                }\n"
        + "            }\n"
        + "        },\n"
        + "        \"childcheck2\":{\n"
        + "            \"healthy\":false\n"
        + "        }\n"
        + "    }\n"
        + "}";
    check(result, noPrettyJson, prettyJson);
  }

  private static void check(HealthCheckResult result, String expNoPrettyJson,
      String expPrettyJson) {
    Assert.assertEquals("non-pretty JSON", expNoPrettyJson, result.toJsonMessage(false));
    Assert.assertEquals("pretty JSON", expPrettyJson, result.toJsonMessage(true));
  }

}
