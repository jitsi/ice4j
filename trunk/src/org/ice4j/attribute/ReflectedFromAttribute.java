/*
 * Stun4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.attribute;

/**
 * The REFLECTED-FROM attribute is present only in Binding Responses,
 * when the Binding Request contained a RESPONSE-ADDRESS attribute.  The
 * attribute contains the identity (in terms of IP address) of the
 * source where the request came from.  Its purpose is to provide
 * traceability, so that a STUN server cannot be used as a reflector for
 * denial-of-service attacks.
 *
 * Its syntax is identical to the MAPPED-ADDRESS attribute.
 *
 * <p>Copyright: Copyright (c) 2003</p>
 * <p>Organisation: Louis Pasteur University, Strasbourg, France</p>
 *                   <p>Network Research Team (http://www-r2.u-strasbg.fr)</p></p>
 * @author Emil Ivov
 * @version 0.1
 */

public class ReflectedFromAttribute extends AddressAttribute
{

    public static final String NAME = "REFLECTED-FROM";

    /**
     * Creates a REFLECTED-FROM attribute
     */
    public ReflectedFromAttribute()
    {
        super(REFLECTED_FROM);
    }

}
