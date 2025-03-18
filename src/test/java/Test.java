import net.raphaelgf.lib.RconServer.*;

public class Test {
    // Entry point
    public static void main(String[] args) {
        RconServer server = new RconServer(25575,new Handler(),System.out,false);
        try {
            server.addUser(new User("user", "password"));
            server.addUser(new User("guest", null));
        } catch (AlreadyExistsPassword e) {
            throw new RuntimeException(e);
        }
        server.start(3,3,10);
    }

    public static void sleep(long ms){
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ignore){}
    }

    private static class Handler implements CommandHandler{
        @Override
        public String command(String username,String command) throws Close {
            if (command.equals("exit")) throw new Close();
            sleep(1000);
            if (username==null) return "The command is : "+command;
            return "Hello "+username+",the command is : "+command;
        }
    }
}