package org.ice4j.oldice;

public class IceException extends Exception
{
  private int id;

  /**
   * Serial version UID for this Serializable class.
   */
  private static final long serialVersionUID = 35367793L;

  public IceException()
  {

  }

  public IceException(String message)
  {
    super(message);
  }
}
