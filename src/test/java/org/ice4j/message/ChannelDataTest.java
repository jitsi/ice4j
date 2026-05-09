package org.ice4j.message;

import org.ice4j.StunException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ChannelDataTest {

  @Rule public final ExpectedException thrown = ExpectedException.none();

  @Test
  public void testDecode() throws StunException {
    final ChannelData channelData =
            ChannelData.decode(new byte[]{64, 0, 0, 0, 1}, '\u0000');
    assertArrayEquals(new byte[]{}, channelData.getData());
    assertEquals('\u4000', channelData.getChannelNumber());

    final ChannelData channelData2 =
            ChannelData.decode(new byte[]{64, 0, 0, 0, 1, 1, 1, 1, 1},
            '\u0000', '\u0000');
    assertArrayEquals(new byte[]{}, channelData2.getData());
    assertEquals('\u4000', channelData2.getChannelNumber());
  }

  @Test
  public void testDecodeExceptionSizeTooShort() throws StunException {
    thrown.expect(StunException.class);
    ChannelData.decode(new byte[] {0, 0, 123, -7, 122, 122, 122}, '\u0007');
    // Method is not expected to return due to exception thrown
  }

  @Test
  public void testDecodeExceptionChannelNumberInvalid() throws StunException {
    thrown.expect(StunException.class);
    ChannelData.decode(new byte[]{0, 0, 32, 0, 33}, '\u0000');
    // Method is not expected to return due to exception thrown
  }

  @Test
  public void testDecodeExceptionSizeMismatch() throws StunException {
    thrown.expect(StunException.class);
    ChannelData.decode(new byte[]{64, 0, 32, 0, 33}, '\u0000');
    // Method is not expected to return due to exception thrown
  }

  @Test
  public void testEncode() throws StunException {
    final ChannelData channelData = new ChannelData();

    channelData.setChannelNumber('\u8001');
    assertArrayEquals(new byte[] {-128, 1, 0, 0}, channelData.encode(false));
    assertArrayEquals(new byte[] {-128, 1, 0, 0}, channelData.encode(true));
    assertArrayEquals(new byte[] {-128, 1, 0, 0}, channelData.encode());

    channelData.setChannelNumber('\u4000');
    channelData.setData(new byte[] {});
    assertArrayEquals(new byte[] {64, 0, 0, 0}, channelData.encode(true));

    channelData.setChannelNumber('\u0001');
    channelData.setData(new byte[] {});
    thrown.expect(StunException.class);
    channelData.encode(true);
    // Method is not expected to return due to exception thrown
  }

  @Test
  public void testGetDataLength() {
    final ChannelData channelData = new ChannelData();

    assertEquals('\u0000', channelData.getDataLength());

    channelData.setData(new byte[] {1, 2, 3});
    assertEquals('\u0003', channelData.getDataLength());
  }

  @Test
  public void testIsChannelDataMessage() {
    assertFalse(ChannelData.isChannelDataMessage(new byte[] {0}));
    assertTrue(ChannelData.isChannelDataMessage(new byte[] {64}));
  }

}
