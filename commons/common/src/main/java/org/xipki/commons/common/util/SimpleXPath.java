/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.common.util;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import javax.xml.xpath.XPathExpressionException;

import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 *
 * @author Lijun Liao
 * @since 2.0
 *
 */
public class SimpleXPath {

  private static class SimpleXPathStep {

    private final String namespaceURI;

    private final String localPart;

    private boolean isElement = true;

    /**
     *
     * @param step
     * @param nsPrefixURIMap Prefix and URI map of namespace. Set it to null if
     *    namespace will not be evaluated.
     */
    SimpleXPathStep(
        final String pStep,
        final Map<String, String> nsPrefixURIMap)
    throws XPathExpressionException {
      String step = pStep;
      if (step.charAt(0) == '@') {
        isElement = false;
        step = step.substring(1);
      }

      int idx = step.indexOf(':');
      String prefix;
      if (idx != -1) {
        prefix = step.substring(0, idx);
        this.localPart = step.substring(idx + 1);
      } else {
        prefix = isElement
            ? ""
            : null;
        this.localPart = step;
      }

      if (nsPrefixURIMap != null && prefix != null) {
        this.namespaceURI = nsPrefixURIMap.get(prefix);
        if (this.namespaceURI == null) {
          throw new XPathExpressionException(
              "could not find namespace for the prefix '" + prefix + "'");
        }
      } else {
        this.namespaceURI = null;
      }
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();
      sb.append(isElement
          ? "Element"
          : "Attribute");
      sb.append(" localPart='");
      sb.append(localPart);
      sb.append("'");
      sb.append(" namespace='");
      sb.append(namespaceURI);
      sb.append("'");
      return sb.toString();
    }

  } // class SimpleXPathStep

  private final List<SimpleXPathStep> steps;

  /**
   *
   * @param relativeXPath
   * @param nsPrefixURIMap Prefix and URI map of namespace. Set it to null if
   *    namespace will not be evaluated.
   * @throws XPathExpressionException
   */
  public SimpleXPath(
      final String relativeXPath,
      final Map<String, String> nsPrefixURIMap)
  throws XPathExpressionException {
    if (relativeXPath.startsWith("/")) {
      throw new XPathExpressionException(relativeXPath + " is no a relative xpath");
    }

    StringTokenizer st = new StringTokenizer(relativeXPath, "/");
    steps = new ArrayList<SimpleXPath.SimpleXPathStep>(st.countTokens());

    int countTokens = st.countTokens();

    int stepNo = 1;
    while (st.hasMoreTokens()) {
      String step = st.nextToken();
      int idx = step.indexOf('@');
      if (idx != -1) {
        if (stepNo != countTokens) {
          throw new XPathExpressionException(
              "attribute is only allowed in the last step");
        } else {
          if (idx > 0) {
            steps.add(new SimpleXPathStep(step.substring(0, idx), nsPrefixURIMap));
          }
          steps.add(new SimpleXPathStep(step.substring(idx), nsPrefixURIMap));
        }
      } else {
        steps.add(new SimpleXPathStep(step, nsPrefixURIMap));
      }

      stepNo++;
    }
  }

  public List<Node> select(
      final Element context) {
    List<Node> rv = new LinkedList<Node>();
    select(rv, context, this.steps, 0, false);
    return rv;
  }

  public Node selectFirstMatch(
      final Element context) {
    List<Node> rv = new LinkedList<Node>();
    select(rv, context, this.steps, 0, true);
    return CollectionUtil.isEmpty(rv)
        ? null
        : rv.get(0);
  }

  private static void select(
      final List<Node> results,
      final Element context,
      final List<SimpleXPathStep> steps,
      final int stepIndex,
      final boolean onlyFirst) {
    if (onlyFirst && CollectionUtil.isNotEmpty(results)) {
      return;
    }

    SimpleXPathStep step = steps.get(stepIndex);
    if (step.isElement) {
      List<Element> children = XMLUtil.getElementChilden(
          context, step.namespaceURI, step.localPart);
      if (steps.size() == stepIndex + 1) {
        results.addAll(children);
      } else {
        for (Element child : children) {
          select(results, child, steps, stepIndex + 1, onlyFirst);
        }
      }
    } else {
      Attr attr = context.getAttributeNodeNS(step.namespaceURI, step.localPart);
      if (attr == null && step.namespaceURI == null) {
        attr = context.getAttributeNode(step.localPart);
      }
      if (attr != null) {
        results.add(attr);
      }
    }
  }

}
