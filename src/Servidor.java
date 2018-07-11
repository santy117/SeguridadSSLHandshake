import java.io.*;
import java.net.*;
import java.security.KeyStore;

import javax.net.ssl.*;

import java.util.Enumeration;
import java.util.Scanner;

public class Servidor {
	public static void main(String[] args){

		// declaramos el puerto donde se va a prestar el servicio

		int port = 9001;
		Scanner teclado = new Scanner(System.in);
		KeyStore ks;
		char[] passphrase = "servidor".toCharArray();

		// pasamos los argumentos de entrada a una funcion secundaria que se encarga de su extraccion y la asignacion de las keyStore/trustStore

		defineKeyStores(args);

		// Iniciamos el SSL socket que se mantiene a la escucha mediante la clase Conexion que implementa el Thread para mantenerse a la escucha

		SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		SSLServerSocket socket = null;
		try {
			socket = (SSLServerSocket)factory.createServerSocket(port);
			System.out.println("Servidor iniciado\nEsperando nuevas solicitudes");
			while (true) {
				String suites[]=new String[6];
				int entero=0;
				//Habilitamos las cipherSuites de SSL en el socket del servidor.
				for(int i=0; i<socket.getSupportedCipherSuites().length; i++) {
					if(socket.getSupportedCipherSuites()[i].startsWith("SSL")) {
						suites[entero]=socket.getSupportedCipherSuites()[i];
						entero++;
					}
				}
				socket.setEnabledCipherSuites(suites);
				Socket cliente = socket.accept(); 
				// Creamos un objeto de la clase Conexion que se encarga de mantenerse a la espera de nuevas solicitudes mediante el Thread

				Conexion conex = new Conexion(cliente, args[4]);
				conex.start();
			}
		} catch (IOException e) {
			//e.printStackTrace();
			System.out.println("Conexion denegada creando socket");
			return;
		}
	}

	// Funcion con la que definimos tanto las propiedades de la keyStore como de la trustStore

	private static void defineKeyStores(String[] args) {
		String raiz = "Stores/Servidor/";

		String pass_keystore = args[1];
		String pass_truststore = args[3];

		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.keyStore", raiz + args[0] + ".jce");
		System.setProperty("javax.net.ssl.keyStorePassword", pass_keystore);
		System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.trustStore", raiz + args[2] + ".jce");
		System.setProperty("javax.net.ssl.trustStorePassword", pass_truststore);
	}
}
