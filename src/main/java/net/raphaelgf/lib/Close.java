package net.raphaelgf.lib;

public class Close extends Exception {
    public Close() {
        super("Connection need to be closed");
    }
}
