package org.krakenapps.pcap.decoder.http.impl;

import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.ChainBuffer;

public abstract class Chunked {

    private Buffer chunked;

    /* CHUNKED variable */
    private int chunkedOffset = 0;
    private int chunkedLength = -1;

    public void createChunked() {
        chunked = new ChainBuffer();
    }

    public int getChunkedOffset() {
        return chunkedOffset;
    }

    public void setChunkedOffset(int chunkedOffset) {
        this.chunkedOffset = chunkedOffset;
    }

    public int getChunkedLength() {
        return chunkedLength;
    }

    public void setChunkedLength(int chunkedLength) {
        this.chunkedLength = chunkedLength;
    }

    public Buffer getChunked() {
        return chunked;
    }

    public byte[] readChunkedBytes() {
        byte[] bytes = new byte[chunked.readableBytes()];
        chunked.gets(bytes);
        return bytes;
    }

}
