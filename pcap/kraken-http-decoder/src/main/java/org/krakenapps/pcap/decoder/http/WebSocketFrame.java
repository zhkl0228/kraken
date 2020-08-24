package org.krakenapps.pcap.decoder.http;

public interface WebSocketFrame {

    enum OpCode {
        /**
         * Opcode for "frame continuation" (0x0).
         */
        CONTINUATION(0x0),

        /**
         * Opcode for "text frame" (0x1).
         */
        TEXT(0x1),

        /**
         * Opcode for "binary frame" (0x2).
         */
        BINARY(0x2),

        /**
         * Opcode for "connection close" (0x8).
         */
        CLOSE(0x8),

        /**
         * Opcode for "ping" (0x9).
         */
        PING(0x9),

        /**
         * Opcode for "pong" (0xA).
         */
        PONG(0xa);
        private final int opcode;
        OpCode(int opcode) {
            this.opcode = opcode;
        }
        public static OpCode valueOf(int opcode) {
            for (OpCode code : values()) {
                if (code.opcode == opcode) {
                    return code;
                }
            }
            throw new IllegalStateException("opcode=0x" + Integer.toHexString(opcode));
        }
    }

    boolean isFin();

    boolean isRsv1();

    boolean isRsv2();

    boolean isRsv3();

    OpCode getOpcode();

    byte[] getPayload();

}
