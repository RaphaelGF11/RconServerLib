package net.raphaelgf.lib;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class RconServer {
    private static final int SERVERDATA_AUTH = 3;
    private static final int SERVERDATA_AUTH_RESPONSE = 2;
    private static final int SERVERDATA_EXECCOMMAND = 2;
    private static final int SERVERDATA_RESPONSE_VALUE = 0;

    private final boolean debug;
    private final int port;
    private final CommandHandler handler;
    private final PrintStream logger;
    private ServerSocket serverSocket;
    private boolean running;
    private ExecutorService threadPool;
    private final ConcurrentHashMap<String, User> users;
    private final BanList ban = new BanList();

    private static class BanList{
        private final HashMap<String,LocalDateTime> bans = new HashMap<>();
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
    public static class Banned extends Exception{
        private Banned(){
            super("User banned");
        }
    }

    public RconServer(int port, CommandHandler handler, PrintStream logger, boolean debug) {
        this.port = port;
        this.handler = handler;
        this.logger = logger;
        this.users = new ConcurrentHashMap<>();
        this.running = false;
        this.debug = debug;
    }

    public RconServer(int port, CommandHandler handler, PrintStream logger) {
        this.port = port;
        this.handler = handler;
        this.logger = logger;
        this.users = new ConcurrentHashMap<>();
        this.running = false;
        this.debug=false;
    }

    public synchronized void addUser(User user) throws AlreadyExistsPassword {
        String pass = user.password;
        if (pass==null) pass = "";

        // Vérifier si le mot de passe existe déjà
        for (User existingUser : users.values()) {
            if (existingUser.password.equals(user.password)) {
                throw new AlreadyExistsPassword("Mot de passe déjà utilisé");
            }
        }

        users.put(pass, user);
        logger.println("[RCON] Utilisateur ajouté: " + (user.username != null ? user.username : "anonyme"));
    }

    public boolean delUser(User user) {
        return delUser(user.password);
    }

    public synchronized boolean delUser(String pass) {
        String passwd = pass;
        if (passwd==null) passwd = "";
        final User user = users.get(passwd);
        if (user==null) return false;
        final String username = user.username;
        users.remove(passwd);
        logger.println("[RCON] Utilisateur retiré: " + (username != null ? username : "anonyme"));
        return true;
    }

    public static class AntiDDOS{
        private final int maxRPS;
        private final HashMap<String,ArrayList<LocalDateTime>> history;
        /**
         * Construis un antiddos
         * @param maxRPS Maximum de requêtes par seconde
         */
        AntiDDOS(int maxRPS){
            this.history = new HashMap<>();
            this.maxRPS = maxRPS;
        }
        private boolean verify(Socket socket) throws IOException {
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

    private int maxLoginTrys = 3;
    private Integer tempBan = 10;

    public synchronized void start(Integer antiDDOSmaxRPS, int maxLoginTrys, Integer tempBan) {
        this.maxLoginTrys = maxLoginTrys;
        this.tempBan = tempBan;
        AntiDDOS antiDDOS;
        if(antiDDOSmaxRPS!=null){
            antiDDOS = new AntiDDOS(antiDDOSmaxRPS);
            logger.println("[RCON] Anti DDOS activé");
        } else antiDDOS = null;
        threadPool = Executors.newCachedThreadPool();
        try {
            serverSocket = new ServerSocket(port);
            running = true;
            logger.println("[RCON] Serveur démarré sur le port " + port);
            while (running) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    logger.println("[RCON] Nouvelle connexion depuis " + clientSocket.getInetAddress().getHostAddress());
                    threadPool.execute(() -> handleClient(clientSocket,antiDDOS));
                } catch (IOException e) {
                    if (running) {
                        logger.println("[RCON] Erreur lors de l'acceptation de la connexion: " + e.getMessage());
                    }
                }
            }

        } catch (IOException e) {
            logger.println("[RCON] Erreur lors du démarrage du serveur: " + e.getMessage());
            stop();
        }
    }

    private void handleClient(Socket clientSocket,AntiDDOS antiDDOS) {
        String clientAddress = clientSocket.getInetAddress().getHostAddress();
        if (antiDDOS!=null) {
            try{
                if (!antiDDOS.verify(clientSocket)) {
                    if (tempBan!=null) ban.ban(clientAddress,tempBan);
                    return;
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        try {
            ban.checkBanned(clientAddress);
        } catch (Banned ignore) {
            try {
                clientSocket.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return;
        }
        User authenticatedUser = null;
        try {
            InputStream inputStream = clientSocket.getInputStream();
            OutputStream outputStream = clientSocket.getOutputStream();
            boolean authenticated = false;

            byte[] headerBuffer = new byte[12]; // Pour lire l'en-tête: length(4) + requestId(4) + type(4)
            byte[] bodyBuffer = new byte[4096]; // Pour lire le reste du paquet

            int trys = 0;

            while (clientSocket.isConnected() && !clientSocket.isClosed() && running) {
                try {
                    ban.checkBanned(clientAddress);
                } catch (Banned ignore) {
                    clientSocket.close();
                    return;
                }
                // Attendre que des données soient disponibles
                if (inputStream.available() < 4) {
                    try {
                        Thread.sleep(50);
                        continue;
                    } catch (InterruptedException e) {
                        logger.println("[RCON] Thread interrompu pour client " + clientAddress);
                        break;
                    }
                }

                // Lire l'en-tête complet (12 octets)
                int bytesRead;
                int totalHeaderBytesRead = 0;

                while (totalHeaderBytesRead < 12) {
                    bytesRead = inputStream.read(headerBuffer, totalHeaderBytesRead, 12 - totalHeaderBytesRead);
                    if (bytesRead <= 0) {
                        logger.println("[RCON] Erreur de lecture de l'en-tête pour client " + clientAddress);
                        break;
                    }
                    totalHeaderBytesRead += bytesRead;
                }

                if (totalHeaderBytesRead < 12) {
                    logger.println("[RCON] En-tête incomplet reçu de client " + clientAddress);
                    break;
                }

                // Convertir les octets en valeurs (little-endian)
                ByteBuffer headerBuf = ByteBuffer.wrap(headerBuffer);
                headerBuf.order(ByteOrder.LITTLE_ENDIAN);

                int length = headerBuf.getInt(0);
                int requestId = headerBuf.getInt(4);
                int type = headerBuf.getInt(8);

                if (debug) logger.println("[RCON] Paquet reçu de " + clientAddress + ", taille: " + length);

                // Vérifier si la longueur est valide
                if (length < 10 || length > 4096) {
                    logger.println("[RCON] Taille de paquet invalide de client " + clientAddress + ": " + length);
                    break;
                }

                // Calculer la taille du corps (payload + 2 octets nuls)
                int bodyLength = length - 8; // Soustraire les 8 octets déjà lus (requestId + type)

                // Lire le corps du paquet
                int totalBodyBytesRead = 0;

                while (totalBodyBytesRead < bodyLength) {
                    bytesRead = inputStream.read(bodyBuffer, totalBodyBytesRead, bodyLength - totalBodyBytesRead);
                    if (bytesRead <= 0) {
                        logger.println("[RCON] Erreur de lecture du corps du paquet de client " + clientAddress);
                        break;
                    }
                    totalBodyBytesRead += bytesRead;
                }

                if (totalBodyBytesRead < bodyLength) {
                    logger.println("[RCON] Corps incomplet reçu de client " + clientAddress);
                    break;
                }

                // Extraire la charge utile (en excluant les deux octets nuls à la fin)
                String payload = new String(bodyBuffer, 0, bodyLength - 2, StandardCharsets.UTF_8);
                if (debug) logger.println("[RCON] ID: " + requestId + ", Type: " + type + ", Payload: " + payload);

                try {
                    ban.checkBanned(clientAddress);
                } catch (Banned ignore) {
                    clientSocket.close();
                    return;
                }
                // Traitement des commandes
                if (type == SERVERDATA_AUTH) {
                    if (antiDDOS!=null) {
                        try{
                            if (!antiDDOS.verify(clientSocket)) {
                                if (tempBan!=null) ban.ban(clientAddress,tempBan);
                                return;
                            }
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                    authenticatedUser = users.get(payload);
                    try {
                        ban.checkBanned(clientAddress);
                    } catch (Banned ignore) {
                        clientSocket.close();
                        return;
                    }
                    if (authenticatedUser != null) {
                        authenticated = true;
                        logger.println("[RCON] Client " + clientAddress + " authentifié avec succès" +
                                (authenticatedUser.username != null ? " en tant que " + authenticatedUser.username : " (anonyme)"));
                        sendResponse(outputStream, requestId, SERVERDATA_AUTH_RESPONSE, "Welcome "+authenticatedUser.username);
                    } else {
                        logger.println("[RCON] Échec d'authentification pour client " + clientAddress);
                        trys++;
                        if (trys>=maxLoginTrys){
                            if (tempBan!=null) ban.ban(clientAddress,tempBan);
                            clientSocket.close();
                            return;
                        }
                        sendResponse(outputStream, -1, SERVERDATA_AUTH_RESPONSE, "");
                    }
                } else if (type == SERVERDATA_EXECCOMMAND) {
                    if (authenticated) {
                        try {
                            // Exécuter la commande via le handler fourni
                            String username = authenticatedUser != null ? authenticatedUser.username : null;
                            String response = handler.command(username, payload);
                            logger.println("[RCON] Client " + clientAddress + " exécute la commande: " + payload);
                            logger.println("[RCON] Réponse: " + response);
                            sendResponse(outputStream, requestId, SERVERDATA_RESPONSE_VALUE, response);
                        } catch (Close e) {
                            logger.println("[RCON] Fermeture de connexion demandée par le handler pour client " + clientAddress);
                            sendResponse(outputStream, requestId, SERVERDATA_RESPONSE_VALUE, "Fermeture de la connexion...");
                            break;
                        }
                    } else {
                        logger.println("[RCON] Client " + clientAddress + " tente d'exécuter sans authentification");
                        sendResponse(outputStream, requestId, SERVERDATA_RESPONSE_VALUE, "Non authentifié");
                    }
                } else {
                    logger.println("[RCON] Type de paquet inconnu depuis client " + clientAddress + ": " + type);
                    sendResponse(outputStream, requestId, SERVERDATA_RESPONSE_VALUE, "Type de paquet inconnu");
                }
            }
        } catch (IOException e) {
            logger.println("[RCON] Erreur lors de la gestion du client " + clientAddress + ": " + e.getMessage());
        } finally {
            try {
                clientSocket.close();
                logger.println("[RCON] Connexion fermée avec " + clientAddress);
            } catch (IOException e) {
                logger.println("[RCON] Erreur lors de la fermeture de la connexion avec " + clientAddress + ": " + e.getMessage());
            }
        }
    }

    private void sendResponse(OutputStream out, int requestId, int type, String response) throws IOException {
        byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
        int length = responseBytes.length + 10; // +8 pour les deux int, +2 pour les deux octets nuls

        ByteBuffer buffer = ByteBuffer.allocate(length + 4); // +4 pour le champ de longueur
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        buffer.putInt(length);
        buffer.putInt(requestId);
        buffer.putInt(type);
        buffer.put(responseBytes);
        buffer.put((byte) 0);
        buffer.put((byte) 0);

        out.write(buffer.array());
        out.flush();
        if (debug) logger.println("[RCON] Réponse envoyée: ID=" + requestId + ", Type=" + type + ", Longueur=" + length);
    }

    public void stop() {
        running = false;

        if (threadPool != null && !threadPool.isShutdown()) {
            threadPool.shutdown();
            logger.println("[RCON] ThreadPool arrêté");
        }

        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
                logger.println("[RCON] Serveur arrêté");
            }
        } catch (IOException e) {
            logger.println("[RCON] Erreur lors de l'arrêt du serveur: " + e.getMessage());
        }
    }

    public boolean isRunning() {
        return running;
    }
}

