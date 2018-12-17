package org.ice4j.util;

import java.util.concurrent.*;

/**
 * Concrete dummy implementation of PacketQueue. Intended for launching tests
 * against base implementation of PacketQueue.
 *
 * @author Yura Yaroshevich
 */
class DummyQueue
    extends PacketQueue<DummyQueue.Dummy>
{
    DummyQueue(
        int capacity,
        PacketHandler<Dummy> packetHandler,
        ExecutorService executor)
    {
        super(capacity, false, false, "DummyQueue", packetHandler,
            executor);
    }

    DummyQueue(int capacity)
    {
        super(capacity, false, false, "DummyQueue", null,     null);
    }

    @Override
    public byte[] getBuffer(Dummy pkt)
    {
        return null;
    }

    @Override
    public int getOffset(Dummy pkt)
    {
        return 0;
    }

    @Override
    public int getLength(Dummy pkt)
    {
        return 0;
    }

    @Override
    public Object getContext(Dummy pkt)
    {
        return null;
    }

    @Override
    protected Dummy createPacket(byte[] buf, int off, int len,
        Object context)
    {
        return new Dummy();
    }

    static class Dummy {
        int id;
    }
}
