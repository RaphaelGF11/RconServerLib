package net.raphaelgf.lib.RconServer;

import java.io.IOException;
import java.net.Socket;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;

class AntiDDOS{
    private final int maxRPS;
    private final HashMap<String, ArrayList<LocalDateTime>> history;
    /**
     * Construis un antiddos
     * @param maxRPS Maximum de requêtes par seconde
     */
    AntiDDOS(int maxRPS){
        this.history = new HashMap<>();
        this.maxRPS = maxRPS;
    }
    public boolean verify(Socket socket) throws IOException {
        final String addr = socket.getInetAddress().getHostAddress();
        final LocalDateTime now = LocalDateTime.now();
        ArrayList<LocalDateTime> connexions = history.get(addr);
        if (connexions==null){
            ArrayList<LocalDateTime> list = new ArrayList<>();
            list.add(now);
            history.put(addr,list);
            return true;
        } else {
            connexions.add(now);
            filter(connexions,now.minusSeconds(1));
            if (connexions.size()>maxRPS){
                socket.close();
                return false;
            } else return true;
        }
    }
    private synchronized void filter(ArrayList<LocalDateTime> connexions,LocalDateTime time){
        while (connexions.get(0).isBefore(time)){
            connexions.remove(0);
        }
    }
}
