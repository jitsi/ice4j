package org.ice4j.util;

import java.util.concurrent.ExecutorService;

/**
 * Concrete dummy implementation of PacketQueue. Intended for launching tests
 * against base implementation of PacketQueue.
 */
class DummyQueue
    extends PacketQueue<DummyQueue.Dummy>
{
    DummyQueue(
        int capacity,
        boolean copy,
        boolean enableStatistics,
        String id,
        PacketHandler<Dummy> packetHandler,
        ExecutorService executor)
    {
        super(capacity, copy, enableStatistics, id, packetHandler,
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
        int seed;
    }
}
