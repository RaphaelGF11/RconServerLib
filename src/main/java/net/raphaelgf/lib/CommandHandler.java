package net.raphaelgf.lib;

public interface CommandHandler {
    String command(String username, String command) throws Close;
}
