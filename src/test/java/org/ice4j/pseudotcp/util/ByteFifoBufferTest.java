/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ice4j.pseudotcp.util;

import java.nio.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.*;

/**
 * 
 * @author Pawel Domas
 */
public class ByteFifoBufferTest
{
    public ByteFifoBufferTest()
    {
    }

    /**
     * Test of Length method, of class ByteFifoBuffer.
     */
    @Test
    public void testLength()
    {
        int expResult = 1000;
        ByteFifoBuffer instance = new ByteFifoBuffer(expResult);
        assertEquals(expResult, instance.length());
        int wSize = 100;
        instance.write(getWData(wSize), wSize);
        int result = instance.length();
        assertEquals(expResult, result);
    }

    /**
     * Test of Read method, of class ByteFifoBuffer.
     */
    @Test
    public void testRead()
    {
        int count = 1024;
        byte[] wData = getWData(count);
        ByteFifoBuffer instance = new ByteFifoBuffer(count);
        instance.write(wData, count);

        byte[] readBuff = new byte[count];
        int result = instance.read(readBuff, count);
        assertEquals(count, result);
        assertArrayEquals(wData, readBuff);

    }
    
    /**
     * Tests reading with an offset for destination buffer
     */
    @Test
    public void testReadWithOffset()
    {
        int count = 1024;
        byte[] wData = getWData(count);
        ByteFifoBuffer instance = new ByteFifoBuffer(count);
        instance.write(wData, count);

        byte[] readBuff = new byte[count];
        int expResult = count / 2;
        int result = instance.read(readBuff, count / 2);
        assertEquals(expResult, result);

        result = instance.read(readBuff, count / 2, count / 2);
        assertEquals(expResult, result);

        assertArrayEquals(wData, readBuff);

    }

    /**
     * return some random array
     * 
     * @param count array size
     */
    private byte[] getWData(int count)
    {
        Random r = new Random();
        byte[] res = new byte[count];
        r.nextBytes(res);
        return res;
    }

    /**
     * Test of GetWriteRemaining method, of class ByteFifoBuffer.
     */
    @Test
    public void testGetWriteRemaining()
    {
        int len = 100;
        ByteFifoBuffer instance = new ByteFifoBuffer(len);
        int expResult = len;
        int result = instance.getWriteRemaining();
        assertEquals(expResult, result);

        int w_size = 23;
        byte[] w_data = getWData(w_size);
        instance.write(w_data, w_size);

        expResult = len - w_size;
        result = instance.getWriteRemaining();
        assertEquals(expResult, result);
    }

    /**
     * Test of GetBuffered method, of class ByteFifoBuffer.
     */
    @Test
    public void testGetBuffered()
    {
        int len = 1000;
        ByteFifoBuffer instance = new ByteFifoBuffer(len);
        int w_len = 100;
        byte[] w_data = getWData(w_len);

        instance.write(w_data, w_len);

        int expResult = w_len;
        int result = instance.getBuffered();
        assertEquals(expResult, result);
        int consume = 5;
        expResult = w_len + consume;
        instance.consumeWriteBuffer(consume);
        result = instance.getBuffered();
        assertEquals(expResult, result);
    }

    /**
     * Test of Write method, of class ByteFifoBuffer.
     */
    @Test
    public void testWrite()
    {
        int len = 2048;
        byte[] data = getWData(len);
        ByteFifoBuffer instance = new ByteFifoBuffer(len);
        int result = instance.write(data, len);
        assertEquals(len, result);

        byte[] read = new byte[len];
        int readCount = instance.read(read, len);
        assertEquals(result, readCount);
        assertArrayEquals(data, read);
    }

    @Test
    public void testWriteWithOffset()
    {
        int len = 2048;
        byte[] data = getWData(len);
        ByteFifoBuffer instance = new ByteFifoBuffer(len);
        int expResult = len / 2;
        int result = instance.write(data, 0, len / 2);
        assertEquals(expResult, result);
        result = instance.write(data, len / 2, len / 2);
        assertEquals(expResult, result);

        byte[] read = new byte[len];
        int readCount = instance.read(read, len);
        assertEquals(len, readCount);
        assertArrayEquals(data, read);
    }

    /**
     * Test of ConsumeWriteBuffer method, of class ByteFifoBuffer.
     */
    @Test
    public void testConsumeWriteBuffer()
    {
        int len = 100;
        ByteFifoBuffer instance = new ByteFifoBuffer(len);
        instance.consumeWriteBuffer(len / 2);
        instance.consumeWriteBuffer(len / 2);
        try
        {
            instance.consumeWriteBuffer(1);
            fail();
        }
        catch (BufferOverflowException e)
        {
        }

        instance = new ByteFifoBuffer(len);
        instance.consumeWriteBuffer(95);
        instance.consumeReadData(40);
        instance.consumeWriteBuffer(20);

    }

    /**
     * Test of SetCapacity method, of class ByteFifoBuffer.
     */
    @Test
    public void testSetCapacity()
    {
        int old_size = 100;
        int new_size = 200;
        ByteFifoBuffer instance = new ByteFifoBuffer(old_size);
        boolean expResult = true;
        instance.write(getWData(old_size), old_size);
        boolean result = instance.setCapacity(new_size);
        assertEquals(expResult, result);

        expResult = false;
        instance.resetWritePosition();
        instance.write(getWData(new_size), new_size);
        result = instance.setCapacity(old_size);
        assertEquals(expResult, result);

    }

    /**
     * Test of ConsumeReadData method, of class ByteFifoBuffer.
     */
    @Test
    public void testConsumeReadData()
    {
        int lCount = 100;
        ByteFifoBuffer instance = new ByteFifoBuffer(lCount);
        instance.write(getWData(lCount), lCount);
        instance.consumeReadData(lCount / 2);
        instance.consumeReadData(lCount / 2);
        try
        {
            instance.consumeReadData(1);
            fail();
        }
        catch (BufferUnderflowException e)
        {
        }

    }

    /**
     * Test of ReadOffset method, of class ByteFifoBuffer.
     */
    @Test
    public void testReadOffset()
    {
        int dst_buff_offset = 0;
        int len = 100;
        byte[] src_buff = getWData(len);
        byte[] dst_buff = new byte[len];
        int offset = 0;
        ByteFifoBuffer instance = new ByteFifoBuffer(len);
        instance.write(src_buff, len);
        int result =
            instance.readOffset(dst_buff, dst_buff_offset, len, offset);
        assertEquals(len, result);
        assertArrayEquals(dst_buff, src_buff);

    }

    /**
     * Test of WriteOffset method, of class ByteFifoBuffer.
     */
    @Test
    public void testWriteOffset()
    {
        int len = 200;
        int dataLen = 100;
        byte[] srcData = getWData(dataLen);
        byte[] data = new byte[dataLen];
        int nOffset = 10;
        ByteFifoBuffer instance = new ByteFifoBuffer(len);
        int result = instance.writeOffset(srcData, dataLen, nOffset);
        int readCount = instance.readOffset(data, 0, dataLen, nOffset);
        assertEquals(result, readCount);
        assertArrayEquals(srcData, data);

        byte[] halfFilled = new byte[dataLen * 2];
        System.arraycopy(srcData, 0, halfFilled, dataLen, dataLen);
        byte[] halfFilledRead = new byte[dataLen * 2];
        instance.readOffset(halfFilledRead, dataLen, dataLen, nOffset);
        assertArrayEquals(halfFilled, halfFilledRead);

        // case when w_pos+offset exceeds current backing array length
        instance = new ByteFifoBuffer(len);
        instance.write(srcData, dataLen);
        instance.write(srcData, dataLen / 2);// current writePos = 150
        instance.read(data, dataLen);// curretn readPos = 100
        instance.writeOffset(srcData, dataLen, 50);

        instance = new ByteFifoBuffer(61440);
        instance.writeOffset(getWData(1384), 1384, 31832);

    }

    @Test
    public void testWriteReadWriteRead()
    {
        int len = 2000;
        ByteFifoBuffer instance = new ByteFifoBuffer(len);
        byte[] wrData = getWData(len * 2);
        int written = 0;
        byte[] readBuff = new byte[wrData.length];
        int read = 0;
        do
        {
            int wrRemaining = instance.getWriteRemaining();
            if (wrRemaining > 0 && written < wrData.length)
            {
                int wrCount = instance.writeOffset(wrData, wrRemaining, 0);
                instance.consumeWriteBuffer(wrCount);
                written += wrCount;
            }
            int readAvailable = instance.getBuffered();
            if (readAvailable > 0)
            {
                int rCount =
                    instance.readOffset(readBuff, read, readAvailable, 0);
                instance.consumeReadData(rCount);
                read += rCount;
            }
        }
        while ((read != wrData.length) || (written != wrData.length));
    }

    @Test
    public void testSomeMultiTest()
    {
        int Alen = 16;
        int Blen = 32;
        int Clen = 64;
        int Dlen = 256;
        int len = Alen + Blen + Clen + Dlen;
        ByteFifoBuffer fifo = new ByteFifoBuffer(len);
        byte[] A = getWData(Alen);
        /*byte[] B =*/ getWData(Blen);
        /*byte[] C =*/ getWData(Clen);
        /*byte[] D =*/ getWData(Dlen);
        byte[] Aread = getWData(Alen);
        /*byte[] Bread =*/ getWData(Blen);
        /*byte[] Cread =*/ getWData(Clen);
        /*byte[] Dread =*/ getWData(Dlen);

        fifo.writeOffset(A, Alen, 0);
        fifo.consumeWriteBuffer(Alen);
        fifo.readOffset(Aread, 0, Alen, 0);
        assertArrayEquals(A, Aread);
    }
}
