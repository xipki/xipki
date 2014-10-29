/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.common;

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
 *
 */
public class SimpleXPath
{
    private final List<SimpleXPathStep> steps;

    /**
     *
     * @param relativeXPath
     * @param nsPrefixURIMap Prefix and URI map of namespace. Set it to null if
     *        namespace will not be evaluated.
     * @throws XPathExpressionException
     */
    public SimpleXPath(String relativeXPath, Map<String, String> nsPrefixURIMap)
    throws XPathExpressionException
    {
        if(relativeXPath.startsWith("/"))
        {
            throw new XPathExpressionException(relativeXPath + " is no a relative xpath");
        }

        StringTokenizer st = new StringTokenizer(relativeXPath, "/");
        steps = new ArrayList<SimpleXPath.SimpleXPathStep>(st.countTokens());

        int countTokens = st.countTokens();

        int stepNo = 1;
        while(st.hasMoreTokens())
        {
            String step = st.nextToken();
            int idx = step.indexOf('@');
            if(idx != -1)
            {
                if(stepNo != countTokens)
                {
                    throw new XPathExpressionException("attribute is only allowed in the last step");
                }
                else
                {
                    if(idx > 0)
                    {
                        steps.add(new SimpleXPathStep(step.substring(0, idx), nsPrefixURIMap));
                    }
                    steps.add(new SimpleXPathStep(step.substring(idx), nsPrefixURIMap));
                }
            }
            else
            {
                steps.add(new SimpleXPathStep(step, nsPrefixURIMap));
            }

            stepNo++;
        }
    }

    public List<Node> select(Element context)
    {
        List<Node> rv = new LinkedList<Node>();
        select(rv, context, this.steps, 0, false);
        return rv;
    }

    public Node selectFirstMatch(Element context)
    {
        List<Node> rv = new LinkedList<Node>();
        select(rv, context, this.steps, 0, true);
        return rv.isEmpty() ? null : rv.get(0);
    }

    private static void select(
            List<Node> results, Element context, List<SimpleXPathStep> steps, int stepIndex, boolean onlyFirst)
    {
        if(onlyFirst && ! results.isEmpty())
        {
            return;
        }

        SimpleXPathStep step = steps.get(stepIndex);
        if(step.isElement)
        {
            List<Element> children = XMLUtil.getElementChilden(
                    context, step.namespaceURI, step.localPart);
            if(steps.size() == stepIndex + 1)
            {
                results.addAll(children);
            }
            else
            {
                for (Element child : children)
                {
                    select(results, child, steps, stepIndex+1, onlyFirst);
                }
            }
        }
        else
        {
            Attr attr = context.getAttributeNodeNS(step.namespaceURI, step.localPart);
            if(attr == null && step.namespaceURI == null)
            {
                attr = context.getAttributeNode(step.localPart);
            }
            if(attr != null)
            {
                results.add(attr);
            }
        }
    }

    private static class SimpleXPathStep
    {
        private final String namespaceURI;
        private final String localPart;
        private boolean isElement = true;
        /**
         *
         * @param step
         * @param nsPrefixURIMap Prefix and URI map of namespace. Set it to null if
         *        namespace will not be evaluated.
         */
        SimpleXPathStep(String step, Map<String, String> nsPrefixURIMap)
        throws XPathExpressionException
        {
            if(step.charAt(0) == '@')
            {
                isElement = false;
                step = step.substring(1);
            }

            int idx = step.indexOf(':');
            String prefix;
            if(idx != -1)
            {
                prefix = step.substring(0, idx);
                this.localPart = step.substring(idx+1);
            }
            else
            {
                prefix = isElement ? "" : null;
                this.localPart = step;
            }

            if(nsPrefixURIMap != null && prefix != null)
            {
                this.namespaceURI = nsPrefixURIMap.get(prefix);
                if(this.namespaceURI == null)
                {
                    throw new XPathExpressionException(
                            "could not find namespace for the prefix '" + prefix + "'");
                }
            }
            else
            {
                this.namespaceURI = null;
            }
        }

        @Override
        public String toString()
        {
            StringBuilder sb = new StringBuilder();
            sb.append(isElement ? "Element" : "Attribute");
            sb.append(" localPart='");
            sb.append(localPart);
            sb.append("'");
            sb.append(" namespace='");
            sb.append(namespaceURI);
            sb.append("'");
            return sb.toString();
        }

    }

}
