package net.raphaelgf.lib.RconServer;

public class Close extends Exception {
    public Close() {
        super("Connection need to be closed");
    }
}
