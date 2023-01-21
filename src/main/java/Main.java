public class Main
{
    public static void main(String[] args) {
        int proxyPort = 43251;

        ProxyServer proxyServer = new ProxyServer(proxyPort);
        Thread thread = new Thread(proxyServer);
        thread.start();
    }
}
