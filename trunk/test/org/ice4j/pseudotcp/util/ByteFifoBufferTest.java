/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 * Maintained by the Jitsi community (https://jitsi.org).
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.ice4j.pseudotcp.util;

import junit.framework.*;
import java.nio.*;
import java.util.*;
import static org.junit.Assert.*;
import org.junit.*;

/**
 *
 * @author Pawel Domas
 */
public class ByteFifoBufferTest extends TestCase
{
    public ByteFifoBufferTest()
    {
    }

    /**
     * Test of Length method, of class ByteFifoBuffer.
     */
    public void testLength()
    {
        //System.out.println("Length");
        int expResult = 1000;
        ByteFifoBuffer instance = new ByteFifoBuffer(expResult);
        assertEquals(expResult, instance.Length());
        int wSize = 100;
        instance.Write(getWData(wSize), wSize);
        int result = instance.Length();
        assertEquals(expResult, result);
    }

    /**
     * Test of Read method, of class ByteFifoBuffer.
     */
    public void testRead()
    {
        //System.out.println("Read");
        int count = 1024;
        byte[] wData = getWData(count);
        ByteFifoBuffer instance = new ByteFifoBuffer(count);
        instance.Write(wData, count);

        byte[] readBuff = new byte[count];
        int expResult = count;
        int result = instance.Read(readBuff, count);
        assertEquals(expResult, result);
        assertArrayEquals(wData, readBuff);

    }

    /**
     * return some random array
     * @param count array size
     * @return 
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
    public void testGetWriteRemaining()
    {
        //System.out.println("GetWriteRemaining");
        int len = 100;
        ByteFifoBuffer instance = new ByteFifoBuffer(len);
        int expResult = len;
        int result = instance.GetWriteRemaining();
        assertEquals(expResult, result);

        int w_size = 23;
        byte[] w_data = getWData(w_size);
        instance.Write(w_data, w_size);

        expResult = len - w_size;
        result = instance.GetWriteRemaining();
        assertEquals(expResult, result);
    }

    /**
     * Test of GetBuffered method, of class ByteFifoBuffer.
     */
    public void testGetBuffered()
    {
        //System.out.println("GetBuffered");
        int len = 1000;
        ByteFifoBuffer instance = new ByteFifoBuffer(len);
        int w_len = 100;
        byte[] w_data = getWData(w_len);

        instance.Write(w_data, w_len);

        int expResult = w_len;
        int result = instance.GetBuffered();
        assertEquals(expResult, result);
        int consume = 5;
        expResult = w_len + consume;
        instance.ConsumeWriteBuffer(consume);
        result = instance.GetBuffered();
        assertEquals(expResult, result);
    }

    /**
     * Test of Write method, of class ByteFifoBuffer.
     */
    public void testWrite()
    {
        //System.out.println("Write");
        int len = 2048;
        byte[] data = getWData(len);
        ByteFifoBuffer instance = new ByteFifoBuffer(len);
        int expResult = len;
        int result = instance.Write(data, len);
        assertEquals(expResult, result);

        byte[] read = new byte[len];
        int readCount = instance.Read(read, len);
        assertEquals(result, readCount);
        assertArrayEquals(data, read);
    }
    
    
    public void testWriteWithOffset()
    {
        //System.out.println("Write");
        int len = 2048;
        byte[] data = getWData(len);
        ByteFifoBuffer instance = new ByteFifoBuffer(len);
        int expResult = len/2;
        int result = instance.Write(data,0, len/2);
        assertEquals(expResult, result);
        result = instance.Write(data, len/2, len/2);
        assertEquals(expResult, result);

        byte[] read = new byte[len];
        int readCount = instance.Read(read, len);
        assertEquals(len, readCount);
        assertArrayEquals(data, read);
    }
    

    /**
     * Test of ConsumeWriteBuffer method, of class ByteFifoBuffer.
     */
    public void testConsumeWriteBuffer()
    {
        //System.out.println("ConsumeWriteBuffer");
        int len = 100;
        ByteFifoBuffer instance = new ByteFifoBuffer(len);
        instance.ConsumeWriteBuffer(len / 2);
        instance.ConsumeWriteBuffer(len / 2);
        try
        {
            instance.ConsumeWriteBuffer(1);
            fail();
        }
        catch (BufferOverflowException e)
        {
        }

        instance = new ByteFifoBuffer(len);
        instance.ConsumeWriteBuffer(95);
        instance.ConsumeReadData(40);
        instance.ConsumeWriteBuffer(20);

    }

    /**
     * Test of SetCapacity method, of class ByteFifoBuffer.
     */
    public void testSetCapacity()
    {
        //System.out.println("SetCapacity");
        int old_size = 100;
        int new_size = 200;
        ByteFifoBuffer instance = new ByteFifoBuffer(old_size);
        boolean expResult = true;
        instance.Write(getWData(old_size), old_size);
        boolean result = instance.SetCapacity(new_size);
        assertEquals(expResult, result);

        expResult = false;
        instance.ResetWritePosition();
        instance.Write(getWData(new_size), new_size);
        result = instance.SetCapacity(old_size);
        assertEquals(expResult, result);

        /*
         * int write_size = old_size; instance = new
         * ByteFifoBuffer(old_size); byte[] written = getWData(write_size);
         * assertEquals(write_size, instance.Write(written, write_size));
         * instance.SetCapacity(new_size); byte[] read = new byte[write_size];
         * instance.Read(read, write_size); assertArrayEquals(written, read);
         */
    }

    /**
     * Test of ConsumeReadData method, of class ByteFifoBuffer.
     */
    public void testConsumeReadData()
    {
        //System.out.println("ConsumeReadData");
        int lCount = 100;
        ByteFifoBuffer instance = new ByteFifoBuffer(lCount);
        instance.Write(getWData(lCount), lCount);
        instance.ConsumeReadData(lCount / 2);
        instance.ConsumeReadData(lCount / 2);
        try
        {
            instance.ConsumeReadData(1);
            fail();
        }
        catch (BufferUnderflowException e)
        {
        }

    }

    /**
     * Test of ReadOffset method, of class ByteFifoBuffer.
     */
    public void testReadOffset()
    {
        //System.out.println("ReadOffset");
        int dst_buff_offset = 0;
        int len = 100;
        byte[] src_buff = getWData(len);
        byte[] dst_buff = new byte[len];
        int offset = 0;
        ByteFifoBuffer instance = new ByteFifoBuffer(len);
        int expResult = len;
        instance.Write(src_buff, len);
        int result = instance.ReadOffset(dst_buff, dst_buff_offset, len, offset);
        assertEquals(expResult, result);
        assertArrayEquals(dst_buff, src_buff);

    }

    /**
     * Test of WriteOffset method, of class ByteFifoBuffer.
     */
    public void testWriteOffset()
    {
        //System.out.println("WriteOffset");
        int len = 200;
        int dataLen = 100;
        byte[] srcData = getWData(dataLen);
        byte[] data = new byte[dataLen];
        int nOffset = 10;
        ByteFifoBuffer instance = new ByteFifoBuffer(len);
        int result = instance.WriteOffset(srcData, dataLen, nOffset);
        int readCount = instance.ReadOffset(data, 0, dataLen, nOffset);
        assertEquals(result, readCount);
        assertArrayEquals(srcData, data);


        byte[] halfFilled = new byte[dataLen * 2];
        System.arraycopy(srcData, 0, halfFilled, dataLen, dataLen);
        byte[] halfFilledRead = new byte[dataLen * 2];
        instance.ReadOffset(halfFilledRead, dataLen, dataLen, nOffset);
        assertArrayEquals(halfFilled, halfFilledRead);

        //case when w_pos+offset exceeds current backing array length
        instance = new ByteFifoBuffer(len);
        instance.Write(srcData, dataLen);
        instance.Write(srcData, dataLen / 2);//current writePos = 150
        instance.Read(data, dataLen);// curretn readPos = 100
        instance.WriteOffset(srcData, dataLen, 50);

        instance = new ByteFifoBuffer(61440);
        instance.WriteOffset(getWData(1384), 1384, 31832);
        
    }
    
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
            int wrRemaining = instance.GetWriteRemaining();
            if (wrRemaining > 0 && written < wrData.length)
            {
                int wrCount = instance.WriteOffset(wrData, wrRemaining, 0);
                instance.ConsumeWriteBuffer(wrCount);
                written += wrCount;
            }
            int readAvailable = instance.GetBuffered();
            if (readAvailable > 0)
            {
                int rCount = instance.ReadOffset(readBuff, read, readAvailable, 0);
                instance.ConsumeReadData(rCount);
                read += rCount;
            }
        }
        while ((read != wrData.length) || (written != wrData.length));
    }
    
    public void testSomeMultiTest()
    {
        int Alen = 16;
        int Blen = 32;
        int Clen = 64;
        int Dlen = 256;
        int len = Alen + Blen + Clen + Dlen;
        ByteFifoBuffer fifo = new ByteFifoBuffer(len);
        byte[] A = getWData(Alen);
        byte[] B = getWData(Blen);
        byte[] C = getWData(Clen);
        byte[] D = getWData(Dlen);
        byte[] Aread = getWData(Alen);
        byte[] Bread = getWData(Blen);
        byte[] Cread = getWData(Clen);
        byte[] Dread = getWData(Dlen);

        fifo.WriteOffset(A, Alen, 0);
        fifo.ConsumeWriteBuffer(Alen);
        fifo.ReadOffset(Aread, 0, Alen, 0);
        assertArrayEquals(A, Aread);
    }
}
