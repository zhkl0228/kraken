package org.krakenapps.pcap.decoder.http.impl;

import org.krakenapps.pcap.decoder.http.HttpDecoder;
import org.krakenapps.pcap.decoder.http.WebSocketFrame;

public class WebSocketFrameImpl implements WebSocketFrame {

    public long length = HttpDecoder.DECODE_NOT_READY;
    public byte[] maskingKey;

    public boolean fin;
    public boolean rsv1;
    public boolean rsv2;
    public boolean rsv3;
    public OpCode opcode;
    public byte[] payload;

    public void decodePayload() {
        if (maskingKey == null) {
            return;
        }
        for (int i = 0; i < payload.length; i++) {
            payload[i] ^= maskingKey[i % 4];
        }
    }

    @Override
    public boolean isFin() {
        return fin;
    }

    @Override
    public boolean isRsv1() {
        return rsv1;
    }

    @Override
    public boolean isRsv2() {
        return rsv2;
    }

    @Override
    public boolean isRsv3() {
        return rsv3;
    }

    @Override
    public OpCode getOpcode() {
        return opcode;
    }

    @Override
    public byte[] getPayload() {
        return payload;
    }

    @Override
    public String toString() {
        return "{" +
                "fin=" + fin +
                ", rsv1=" + rsv1 +
                ", rsv2=" + rsv2 +
                ", rsv3=" + rsv3 +
                ", opcode=" + opcode +
                '}';
    }
}
