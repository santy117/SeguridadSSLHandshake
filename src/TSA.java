import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.net.*;
import javax.net.ssl.*;
import java.lang.ClassNotFoundException;
import java.util.Date;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import java.security.cert.CertificateException;

public class TSA {
	public static void main(String[] args) {

		// Realizamos la conexion con el TSA en el puerto 9002

		int port = 9002;

		// Llamamos a la funcion defineKeyStores para definir las propiedades para el acceso a la keyStore

		defineKeyStores();

		// Iniciamos el socket SSL

		SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		ServerSocket socket = null;
		try {
			socket = factory.createServerSocket(port);
			while (true) {
				Socket cliente = socket.accept();
				System.out.println("Conexion establecida con TSA\nCreando sello temporal");

				// Declaramos las variables que utilizaremos posteriormente para recibir y enviar las solicitudes

				ObjectInputStream in = new ObjectInputStream(cliente.getInputStream());
				ObjectOutputStream out = new ObjectOutputStream(cliente.getOutputStream());

				// Extraemos un objeto con la solicitud a nuestro servicio

				Sello_Temporal solicitud = (Sello_Temporal) in.readObject();
				byte[] hash = solicitud.getHashDoc();
				String sello = new Date().toString();
				ByteArrayOutputStream concat = new ByteArrayOutputStream();
				concat.write(hash);
				concat.write(sello.getBytes());
				byte[] firmar_TSA = concat.toByteArray();
				concat.close();
				byte[] SigTSA = firmar(firmar_TSA, obtenerClavePrivada());

				// Enviamos la respuesta a la solicitud de sello temporal

				System.out.println("El sello temporal se ha creado con exito\nEnviando respuesta a la solicitud");
				Sello_Temporal respuesta = new Sello_Temporal();
				respuesta.setSelloTemporal(sello);
				respuesta.setSigTSA(SigTSA);
				out.writeObject(respuesta);

				System.out.println("Envio correcto");
			}
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println("Conexion finalizada");
			return;
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// Funcion con la que obtenemos la clave privada de la store creada anteriormente

	public static PrivateKey obtenerClavePrivada() throws Exception {

		KeyStore ks;
		char[] ks_password = "tsatsa".toCharArray();
		char[] key_password = "tsatsa".toCharArray();
		String ks_file = "Stores/TSA/KS_TSA.jce";

		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream(ks_file), ks_password);
		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry("key_dsa",
				new KeyStore.PasswordProtection(key_password));

		return pkEntry.getPrivateKey();
	}

	// Funcion con la que firmamos el documento con la clave privada introducida por parametros

	public static byte[] firmar(byte[] documento, PrivateKey pk)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableEntryException, InvalidKeyException, SignatureException {

		System.out.println("Se ha solicitado firmar el documento");

		ByteArrayInputStream mensaje = new ByteArrayInputStream(documento);

		// Declaramos las variables que vamos a utilizar

		String algoritmo = "SHA1withDSA";
		int longbloque;
		byte bloque[] = new byte[1024];
		long filesize = 0;

		// Declaramos un objeto de la clase Signature e implementamos el algoritmo de firma que hemos especificado arriba

		Signature signer = Signature.getInstance(algoritmo);
		signer.initSign(pk);

		byte[] firma;

		while ((longbloque = mensaje.read(bloque)) > 0) {
			filesize = filesize + longbloque;
			signer.update(bloque, 0, longbloque);
		}

		firma = signer.sign();

		System.out.println("Documento firmado correctamente. La firma es: ");
		for (int i = 0; i < firma.length; i++) {
			System.out.print(firma[i] + " ");
		}
		System.out.println();
		mensaje.close();

		return firma;

	}

	// Funcion que empleamos para definir las propiedades de las Stores del TSA

	private static void defineKeyStores() {
		String raiz = "Stores/TSA/";

		String pass_keystore = "tsatsa";

		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.keyStore", raiz + "KS_TSA.jce");
		System.setProperty("javax.net.ssl.keyStorePassword", pass_keystore);
	}
}