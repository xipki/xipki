package org.xipki.ca.gateway.acme;

import java.util.regex.Pattern;

public interface ContactVerifier {

  int invalidContact = 1;

  int unsupportedContact = 2;

  int verfifyContact(String contact);

  class DfltContactVerifier implements ContactVerifier {

    private final Pattern pattern = Pattern.compile(
        "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@" + "[_A-Za-z0-9-]+(\\.[_A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$");

    public DfltContactVerifier() {
    }

    @Override
    public int verfifyContact(String contact) {
      if (contact == null || !contact.startsWith("mailto:")) {
        return unsupportedContact;
      }

      return pattern.matcher(contact.substring(7)).matches() ? 0 : invalidContact;
    }
  }

}
