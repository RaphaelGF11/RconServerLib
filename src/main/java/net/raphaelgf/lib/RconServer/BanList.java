package net.raphaelgf.lib.RconServer;

import java.time.LocalDateTime;
import java.util.HashMap;

class BanList{
    private final HashMap<String, LocalDateTime> bans = new HashMap<>();
    public void ban(String key,int seconds){
        bans.put(key,LocalDateTime.now().plusSeconds(seconds));
    }
    public void checkBanned(String key) throws Banned{
        LocalDateTime ban = bans.get(key);
        if (ban!=null) {
            if (ban.isBefore(LocalDateTime.now())){
                bans.remove(key);
            } else throw new Banned();
        }
    }
}
