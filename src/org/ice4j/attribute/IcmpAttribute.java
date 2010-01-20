/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.attribute;

import java.lang.*;

import org.ice4j.*;

/**
 * The ICMP attribute is used to forward
 * to the TURN client some ICMP information.
 *
 * @author Sebastien Vincent
 */
public class IcmpAttribute extends Attribute
{
  /**
   * Attribute name.
   */
  public static final String NAME = "ICMP";

  /**
   * The length of the data contained by this attribute.
   */
  public static final char DATA_LENGTH = 4;

  /**
   * Type value.
   */
  byte type = 0;

  /**
   * Code value.
   */
  byte code = 0;

  /**
   * Constructor.
   */
  IcmpAttribute()
  {
    super(ICMP);
  }

  /**
   * Compares two STUN Attributes. Attributeas are considered equal when their
   * type, length, and all data are the same.
   * @param obj the object to compare this attribute with.
   * @return true if the attributes are equal and false otherwise.
   */
  public boolean equals(Object obj)
  {
    if (! (obj instanceof IcmpAttribute)
        || obj == null)
      return false;

    if (obj == this)
      return true;

    IcmpAttribute att = (IcmpAttribute) obj;
    if (att.getAttributeType()   != getAttributeType()
        || att.getDataLength()   != getDataLength()
        /* compare data */
        || att.type != type
        || att.code != code
       )
      return false;

    return true;
  }

  /**
   * Returns the human readable name of this attribute. Attribute names do
   * not really matter from the protocol point of view. They are only used
   * for debugging and readability.
   * @return this attribute's name.
   */
  public String getName()
  {
    return NAME;
  }

  /**
   * Returns the length of this attribute's body.
   * @return the length of this attribute's value (8 bytes).
   */
  public char getDataLength()
  {
    return DATA_LENGTH;
  }

  /**
   * Returns a binary representation of this attribute.
   * @return a binary representation of this attribute.
   */
  public byte[] encode()
  {
    byte binValue[] = new byte[HEADER_LENGTH + DATA_LENGTH];

    //Type
    binValue[0] = (byte)(getAttributeType()>>8);
    binValue[1] = (byte)(getAttributeType()&0x00FF);
    //Length
    binValue[2] = (byte)(getDataLength() >> 8);
    binValue[3] = (byte)(getDataLength() & 0x00FF);
    //Data
    binValue[4] = type;
    binValue[5] = code;
    binValue[6] = 0x00; /* must be 0 */
    binValue[7] = 0x00; /* must be 0 */

    return binValue;
  }

  /**
   * Sets this attribute's fields according to attributeValue array.
   * @param attributeValue a binary array containing this attribute's field
   *                       values and NOT containing the attribute header.
   * @param offset the position where attribute values begin (most often
   *          offset is equal to the index of the first byte after
   *          length)
   * @param length the length of the binary array.
   * @throws StunException if attrubteValue contains invalid data.
   */
  void decodeAttributeBody(byte[] attributeValue, char offset, char length) throws StunException
  {
    if(length != 4)
    {
      throw new StunException("length invalid");
    }

    type = attributeValue[0];
    code = attributeValue[1];
  }

  /**
   * Set the ICMP type.
   * @param type ICMP type
   */
  public void setType(byte type)
  {
    this.type = type;
  }

  /**
   * Set the ICMP code.
   * @param code ICMP code
   */
  public void setCode(byte code)
  {
    this.code = code;
  }

  /**
   * Get the type.
   * @return ICMP type
   */
  public byte getType()
  {
    return type;
  }

  /**
   * Get the code.
   * @return ICMP code
   */
  public byte getCode()
  {
    return code;
  }
}

