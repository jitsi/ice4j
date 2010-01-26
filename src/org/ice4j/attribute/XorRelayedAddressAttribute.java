/*
 * Ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.attribute;

import org.ice4j.*;

/**
 * The XOR-RELAYED-ADDRESS attribute is given by a TURN server to
 * indicates the client its relayed address.
 *
 * It has the same format as XOR-MAPPED-ADDRESS.
 *
 * @author Sebastien Vincent
 * @version 0.1
 */
public class XorRelayedAddressAttribute extends XorMappedAddressAttribute
{
  /**
   * Attribute name.
   */
  public static final String NAME = "XOR-RELAYED-ADDRESS";

  /**
   * Constructor.
   */
  XorRelayedAddressAttribute()
  {
    super(XOR_RELAYED_ADDRESS);
  }
}

