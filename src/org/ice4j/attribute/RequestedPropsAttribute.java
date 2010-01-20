/*
 * Ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.attribute;

import java.lang.*;

import org.ice4j.*;

/**
 * The REQUESTED-PROPS attribute is used to ask the TURN
 * server some things to do.
 *
 * There are three flags supported : <br/>
 * E : ask an even port;<br/>
 * R : ask to reserve a second port (MUST be set with E flag);<br/>
 * P : ask a preserving allocation.<br/>
 *
 * @author Sebastien Vincent
 * @version 0.1
 */
public class RequestedPropsAttribute extends Attribute
{
  /**
   * Attribute name.
   */
  public static final String NAME = "REQUESTED-PROPS";

  /**
   * The length of the data contained by this attribute.
   */
  public static final char DATA_LENGTH = 4;

  /**
   * E flag.
   */
  boolean eFlag = false;

  /**
   * R flag.
   */
  boolean rFlag = false;

  /**
   * P flag.
   */
  boolean pFlag = false;

  /**
   * Constructor.
   */
  RequestedPropsAttribute()
  {
    super(REQUESTED_PROPS);
  }

  /**
   * Compares two STUN Attributes. Attributeas are considered equal when their
   * type, length, and all data are the same.
   * @param obj the object to compare this attribute with.
   * @return true if the attributes are equal and false otherwise.
   */
  public boolean equals(Object obj)
  {
    if (! (obj instanceof RequestedPropsAttribute)
        || obj == null)
      return false;

    if (obj == this)
      return true;

    RequestedPropsAttribute att = (RequestedPropsAttribute) obj;
    if (att.getAttributeType()   != getAttributeType()
        || att.getDataLength()   != getDataLength()
        /* compare data */
        || att.eFlag != eFlag  || att.rFlag != rFlag || att.pFlag != pFlag
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
    binValue[4] = (byte)((eFlag ? 1 << 8 : 0) + (rFlag ? 1 << 7 : 0) + (pFlag ? 1 << 6 : 0));
    binValue[5] = 0x00; /* not used for the moment */
    binValue[6] = 0x00; /* not used for the moment */
    binValue[7] = 0x00; /* not used for the moment */

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

    eFlag = (attributeValue[0] & 0x80) > 0;
    rFlag = (attributeValue[0] & 0x40) > 0;
    pFlag = (attributeValue[0] & 0x20) > 0 ;
  }

  /**
   * Set the E flag.
   * @param eFlag true of false
   */
  public void setEFlag(boolean eFlag)
  {
    this.eFlag = eFlag;
  }
  
  /**
   * Set the R flag.
   * @param rFlag true of false
   */
  public void setRFlag(boolean rFlag)
  {
    this.rFlag = rFlag;
  }

  /**
   * Set the P flag.
   * @param pFlag true of false
   */
  public void setPFlag(boolean pFlag)
  {
    this.pFlag = pFlag;
  }

  /**
   * Is the E flag set
   * @return true if it is, false otherwise
   */
  public boolean isEFlag()
  {
    return eFlag;
  }

  /**
   * Is the R flag set
   * @return true if it is, false otherwise
   */
  public boolean isRFlag()
  {
    return rFlag;
  }

  /**
   * Is the P flag set
   * @return true if it is, false otherwise
   */
  public boolean isPFlag()
  {
    return pFlag;
  }
}

