# Purpose
The push API is a mode in which ice4j passes received payload packets to the application directly via a callback, 
instead of making them available for reading from a virtual DatagramSocket. This avoids packets being copied into queues
handled by different threads, and is intended to reduce the workload and delay.

# Use
First, the API has to be enabled in configuration by setting `ice4j.use-push-api=true`.

Then, a callback for payload packets needs to be configured for each `Component` using `setBufferCallback()`.

Finally, sending data should be done via `Component.send(byte[] data, int offset, int length)` instead of one of the
virtual sockets.

# Memory model
Buffers for each packet are allocated using `BufferPool.getBuffer`, which can be set externally. The default 
implementation just allocates new memory on the java heap.

If a buffer is not passed to the application, it will be returned via `BufferPool.returnBuffer`. Otherwise, it is the
responsibility of the application.

Two new config options can be used to specify a non-zero offset and space to be left at the end of the buffers (which
could be used to e.g. make RTP processing more efficient):

```AbstractUdpListener.BYTES_TO_LEAVE_AT_START_OF_PACKET```
```AbstractUdpListener.BYTES_TO_LEAVE_AT_END_OF_PACKET```

# Limitations
The push API currently only supports `SinglePortUdpHarvester`. If the application uses regular `HostCandidate`s, it
has to read the packets from a `DatagramSocket`. Sending via `Component.send()` works either way.
