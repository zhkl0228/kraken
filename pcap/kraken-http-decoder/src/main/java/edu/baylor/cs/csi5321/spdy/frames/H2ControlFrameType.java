package edu.baylor.cs.csi5321.spdy.frames;

/**
 *
 * @author Lukas Camra
 */
public enum H2ControlFrameType {

    DATA(0),
    HEADERS(1), PRIORITY(2), RST_STREAM(3), SETTINGS(4), PUSH_PROMISE(5),
    PING(6), GOAWAY(7), WINDOW_UPDATE(8), CONTINUATION(9);
    
    private final short value;

    private H2ControlFrameType(int value) {
        this.value = (short) value;
    }
    
    public short getValue() {
        return value;
    }
    
    public static H2ControlFrameType getEnumTypeFromType(short type) {
        for(H2ControlFrameType t : H2ControlFrameType.values()) {
            if(t.getValue() == type) {
                return t;
            }
        }
        return null;
    }
}
