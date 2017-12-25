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

package org.xipki.common.util;

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
 * @since 2.0.0
 *
 */
public class SimpleXpath {

    private static class SimpleXpathStep {

        private final String namespaceUri;

        private final String localPart;

        private boolean isElement = true;

        /**
         *
         * @param step the step
         * @param nsPrefixUriMap Prefix and URI map of namespace. Set it to null if
         *        namespace will not be evaluated.
         */
        SimpleXpathStep(final String step, final Map<String, String> nsPrefixUriMap)
            throws XPathExpressionException {
            String tmpStep = ParamUtil.requireNonBlank("step", step);
            if (tmpStep.charAt(0) == '@') {
                isElement = false;
                tmpStep = tmpStep.substring(1);
            }

            int idx = tmpStep.indexOf(':');
            String prefix;
            if (idx != -1) {
                prefix = tmpStep.substring(0, idx);
                this.localPart = tmpStep.substring(idx + 1);
            } else {
                prefix = isElement ? "" : null;
                this.localPart = tmpStep;
            }

            if (nsPrefixUriMap != null && prefix != null) {
                this.namespaceUri = nsPrefixUriMap.get(prefix);
                if (this.namespaceUri == null) {
                    throw new XPathExpressionException(
                            "could not find namespace for the prefix '" + prefix + "'");
                }
            } else {
                this.namespaceUri = null;
            }
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(isElement ? "Element" : "Attribute");
            sb.append(" localPart='").append(localPart).append("'");
            sb.append(" namespace='").append(namespaceUri).append("'");
            return sb.toString();
        }

    } // class SimpleXPathStep

    private final List<SimpleXpathStep> steps;

    /**
     *
     * @param relativeXpath the relative XPath
     * @param nsPrefixUriMap Prefix and URI map of namespace. Set it to null if
     *        namespace will not be evaluated.
     * @throws XPathExpressionException if the XPath expression is invalid
     */
    public SimpleXpath(final String relativeXpath, final Map<String, String> nsPrefixUriMap)
            throws XPathExpressionException {
        ParamUtil.requireNonBlank("relativeXpath", relativeXpath);
        if (relativeXpath.startsWith("/")) {
            throw new XPathExpressionException(relativeXpath + " is no a relative xpath");
        }

        StringTokenizer st = new StringTokenizer(relativeXpath, "/");
        steps = new ArrayList<SimpleXpath.SimpleXpathStep>(st.countTokens());

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
                        steps.add(new SimpleXpathStep(step.substring(0, idx), nsPrefixUriMap));
                    }
                    steps.add(new SimpleXpathStep(step.substring(idx), nsPrefixUriMap));
                }
            } else {
                steps.add(new SimpleXpathStep(step, nsPrefixUriMap));
            }

            stepNo++;
        }
    }

    public List<Node> select(final Element context) {
        List<Node> rv = new LinkedList<Node>();
        select(rv, context, this.steps, 0, false);
        return rv;
    }

    private static void select(final List<Node> results, final Element context,
            final List<SimpleXpathStep> steps, final int stepIndex, final boolean onlyFirst) {
        if (onlyFirst && CollectionUtil.isNonEmpty(results)) {
            return;
        }
        ParamUtil.requireNonNull("context", context);
        ParamUtil.requireNonNull("steps", steps);

        SimpleXpathStep step = steps.get(stepIndex);
        if (step.isElement) {
            List<Element> children = XmlUtil.getElementChilden(
                    context, step.namespaceUri, step.localPart);
            if (steps.size() == stepIndex + 1) {
                results.addAll(children);
            } else {
                for (Element child : children) {
                    select(results, child, steps, stepIndex + 1, onlyFirst);
                }
            }
        } else {
            Attr attr = context.getAttributeNodeNS(step.namespaceUri, step.localPart);
            if (attr == null && step.namespaceUri == null) {
                attr = context.getAttributeNode(step.localPart);
            }
            if (attr != null) {
                results.add(attr);
            }
        }
    }

    public Node selectFirstMatch(final Element context) {
        List<Node> rv = new LinkedList<Node>();
        select(rv, context, this.steps, 0, true);
        return CollectionUtil.isEmpty(rv) ? null : rv.get(0);
    }

}
