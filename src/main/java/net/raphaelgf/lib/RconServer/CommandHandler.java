package net.raphaelgf.lib.RconServer;

public interface CommandHandler {
    String command(String username, String command) throws Close;
}
