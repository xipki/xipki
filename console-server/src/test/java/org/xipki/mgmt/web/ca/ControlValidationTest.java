// License Apache License 2.0

package org.xipki.mgmt.web.ca;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.xipki.mgmt.web.ca.CaDomain.*;

/**
 * @author palos
 */
class ControlValidationTest {
  @Test
  void preservesCrlSemanticValidation() {
    for (String c :
        new String[] {
          "interval.hours=5",
          "fullcrl.intervals=0",
          "deltacrl.intervals=-1",
          "fullcrl.intervals=7,deltacrl.intervals=7",
          "interval.time=25:00",
          "exclude.reason=yes",
          "invalidity.date=unrecognized"
        }) {
      assertThrows(IllegalArgumentException.class, () -> new CrlControl(c), c);
    }
    assertDoesNotThrow(
        () -> new CrlControl("interval.hours=6,fullcrl.intervals=4,deltacrl.intervals=1"));
  }

  @Test
  void preservesCtAndSuspensionValidation() {
    assertThrows(IllegalArgumentException.class, () -> new CtlogControl("enabled=true"));
    assertThrows(
        IllegalArgumentException.class,
        () -> new CtlogControl("enabled=yes,servers=https://ct.example"));
    assertThrows(IllegalArgumentException.class, () -> new RevokeSuspendedControl("enabled=yes"));
    assertThrows(
        IllegalArgumentException.class, () -> new RevokeSuspendedControl("targetReason=invalid"));
    assertThrows(
        IllegalArgumentException.class, () -> new RevokeSuspendedControl("unchangedSince=invalid"));
  }
}
