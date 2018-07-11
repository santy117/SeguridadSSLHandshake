import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.net.*;
import javax.net.ssl.*;
import java.lang.ClassNotFoundException;
import java.util.Date;
import java.util.Enumeration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

//La clase conexion hemos indicado que hereda de Thread para que se mantenga a la escucha sin ser interrumpido

/*
 * Códigos para los errores:
 * 1.- Certificado incorrecto.
 * 2.- Firma incorrecta
 * 3.- Documento no existente en la base de datos
 * 4.- Acceso al documento no permitido
 */
public class Conexion extends Thread {

	Socket cliente;
	static int idRegistro;
	String algoritmoCifrado;

	// Constructor para la creacion de nuevas conexiones, le pasamos por parametros el socket y el algoritmo de cifrado

	public Conexion(Socket c, String a) {
		cliente = c;
		algoritmoCifrado = a;
	}

	public void run() {
		try {

			System.out.println("Conexion establecida");
			ObjectInputStream in = new ObjectInputStream(cliente.getInputStream());
			ObjectOutputStream out = new ObjectOutputStream(cliente.getOutputStream());
			Peticion respuesta;
			while (true) {
				Peticion solicitud = (Peticion) in.readObject();
				switch (solicitud.getTipo()) {
				case "REGISTRAR_DOCUMENTO":

					// Opcion Registrar Documento

					System.out.println("Se ha recibido una peticion de registro de documento");

					// Verificamos si la firma del documento es correcta
					if (!verificarCertFirmaC(solicitud.getCertFirmaC())) {
						System.out.println("CERTIFICADO INCORRECTO");
						respuesta = new Peticion();
						respuesta.setNError(1);
						out.writeObject(respuesta);
						break;
					}
					else System.out.println("CERTIFICADO CORRECTO");
					if (!verificar(solicitud.getDocumento(), solicitud.getFirmaDoc())) {
						System.out.println("FIRMA INCORRECTA");
						respuesta = new Peticion();
						respuesta.setNError(2);
						out.writeObject(2);
						break;
					}
					else System.out.println("FIRMA CORRECTA");

					// Aumentamos el id de Registro para llevar una referencia(id)
					// de cada uno de los ficheros registrados
					// comprobando ademas que no coincida con el ID de registro de
				//	 algun fichero ya registrado

					File almacen = new File("Recursos/Servidor");
					File[] listaFicheros = almacen.listFiles();
					boolean onelap;
					do {
						onelap=false;
						for (int i = 0; i < listaFicheros.length; i++) {
							if (listaFicheros[i].getName().startsWith(Integer.toString(idRegistro))) {
								idRegistro++;
								onelap=true;
							}
						}
					}while(onelap);

					Sello_Temporal selloTemporal = pedirSello(solicitud.getDocumento());
					ByteArrayOutputStream concat = new ByteArrayOutputStream();
					concat.write((byte) idRegistro);
					concat.write(selloTemporal.getSelloTemporal().getBytes());
					concat.write(selloTemporal.getSigTSA());
					concat.write(solicitud.getDocumento());
					concat.write(solicitud.getFirmaDoc());
					byte[] firmar_servidor = concat.toByteArray();
					concat.close();

					// Firmamos el documento con la clave privada

					byte[] SigRD = firmar(firmar_servidor, obtenerClavePrivada());
					File guardar;
					byte[] doc;

					// Comprobamos el tipo de confidencialidad con el que se ha registrado y almacenamos el fichero

					if (solicitud.getConfidencialidad().equals("PRIVADO")) {
						System.out.println("Cifrando documento");
						doc = cifrarDocumento(solicitud.getNombreDoc(), solicitud.getDocumento(), algoritmoCifrado);
						guardar = new File(
								"Recursos/Servidor/" + idRegistro + "_" + solicitud.getIdPropietario() + ".sig.cif");
					} else {
						doc = solicitud.getDocumento();
						guardar = new File(
								"Recursos/Servidor/" + idRegistro + "_" + solicitud.getIdPropietario() + ".sig");
					}
					PrintWriter escribir = new PrintWriter(guardar);
					for (int i = 0; i < solicitud.getFirmaDoc().length; i++) {
						escribir.print(solicitud.getFirmaDoc()[i] + " ");
					}
					escribir.println();
					escribir.println(solicitud.getNombreDoc());
					escribir.println(idRegistro);
					escribir.println(selloTemporal.getSelloTemporal());
					for (int i = 0; i < selloTemporal.getSigTSA().length; i++) {
						escribir.print(selloTemporal.getSigTSA()[i] + " ");
					}
					escribir.println();
					for (int i = 0; i < SigRD.length; i++) {
						escribir.print(SigRD[i] + " ");
					}
					escribir.println();
					for (int i = 0; i < doc.length; i++) {
						escribir.print(doc[i] + " ");
					}
					escribir.println();
					escribir.close();

					// Enviamos al cliente la informacion del documento que acaba de registrar; el id del documento, el sello temporal y el sigRD

					System.out.println("Registro correcto. Enviando la respuesta al cliente");
					respuesta = new Peticion();
					respuesta.setIdRegistro(idRegistro);
					respuesta.setSelloTemporal(selloTemporal);
					respuesta.setSigRD(SigRD);
					respuesta.setCertFirmaS(getCertFirmaS());
					out.writeObject(respuesta);
					System.out.println("Envio correcto");

					break;
				case "RECUPERAR_DOCUMENTO":

					// Opcion Recuperar Documento

					System.out.println("Se ha recibido una solicitud de recuperacion de documento");

					// Cargamos la carpeta donde tenemos alojados los documentos

					File almacenServid = new File("Recursos/Servidor");
					File[] fichers = almacenServid.listFiles();
					int fileName = solicitud.getIdRegistro();
					File wanted = null;

					// Buscamos el documento

					for (int i = 0; i < fichers.length; i++) {
						if (fichers[i].getName().startsWith(Integer.toString(fileName))) {
							wanted = fichers[i];
						}
					}
					if (wanted == null) {
						respuesta = new Peticion();
						respuesta.setNError(3);
						out.writeObject(respuesta);
						System.out.println("El documento no existe");
						break;
					} else {
						if (wanted.getName().endsWith(".cif")) {
							String idPropietar = wanted.getName().split("_")[1].split("\\.")[0];

							// en caso de el solicitante no ser quien lo ha registrado y el documento ser privado se niega el acceso

							if (!getIdPropietario(solicitud.getCertAuthC()).equals(idPropietar)) {
								respuesta=new Peticion();
								respuesta.setNError(4);
								out.writeObject(respuesta);
								System.out.println("No se permite el acceso");
								break;
							}
						}
					}

					// Extraemos los datos del documento ya localizado

					Scanner ficher = new Scanner(new File("Recursos/Servidor/" + wanted.getName()));
					String firmaDo = ficher.nextLine();
					String nombreDo = ficher.nextLine();
					int idRegistr = Integer.parseInt(ficher.nextLine());
					Sello_Temporal sello_recuper = new Sello_Temporal();
					sello_recuper.setSelloTemporal(ficher.nextLine());
					String SigT = ficher.nextLine();
					String SigR = ficher.nextLine();
					String docu = ficher.nextLine();
					String[] SigTArray = SigT.split(" ");
					byte[] SigTByte = new byte[SigTArray.length];

					// Procesamos los datos extraidos

					for (int i = 0; i < SigTArray.length; i++) {
						SigTByte[i] = Byte.parseByte(SigTArray[i]);
					}
					sello_recuper.setSigTSA(SigTByte);
					String[] firmaDoArray = firmaDo.split(" ");
					byte[] firmaDoByte = new byte[firmaDoArray.length];
					for (int i = 0; i < firmaDoArray.length; i++) {
						firmaDoByte[i] = Byte.parseByte(firmaDoArray[i]);
					}
					String[] SigRArray = SigR.split(" ");
					byte[] SigRByte = new byte[SigRArray.length];
					for (int i = 0; i < SigRArray.length; i++) {
						SigRByte[i] = Byte.parseByte(SigRArray[i]);
					}
					String[] docuArray = docu.split(" ");
					byte[] docuByte = new byte[docuArray.length];
					for (int i = 0; i < docuArray.length; i++) {
						docuByte[i] = Byte.parseByte(docuArray[i]);
					}

					for (int i = 0; i < 50; i++) {
						System.out.print(docuByte[i] + " ");
					}
					System.out.println();
					for (int i = 0; i < SigRByte.length; i++) {
						System.out.print(SigRByte[i] + " ");
					}
					System.out.println();

					// Formamos el objeto que va a ser enviado al solicitante

					respuesta = new Peticion();
					respuesta.setFirmaDoc(firmaDoByte);
					respuesta.setNombreDoc(nombreDo);
					respuesta.setIdRegistro(idRegistr);
					respuesta.setSelloTemporal(sello_recuper);
					byte[] docuByteCif;

					// En caso de ser privado el documento lo desciframos, en otro caso lo enviamos sin llamar a la funcion descifrar

					if (wanted.getName().endsWith(".cif")) {
						docuByteCif = descifrarDocumento(nombreDo, docuByte, algoritmoCifrado);
					} else
						docuByteCif = docuByte;
					respuesta.setDocumento(docuByteCif);
					respuesta.setSigRD(SigRByte);
					respuesta.setCertFirmaS(getCertFirmaS());

					// Enviamos el objeto respuesta con el documento solicitado al cliente

					out.writeObject(respuesta);
					System.out.println("El documento se ha enviado al cliente con exito");
					break;
				case "LISTAR_DOCUMENTOS":

					// Opcion Listar Documentos

					System.out.println("Se ha solicitado el envio de la lista de documentos en el servidor");
					ArrayList<String> ListaDocPublicos = new ArrayList<String>();
					ArrayList<String> ListaDocPrivados = new ArrayList<String>();

					/*
					  Extraemos una lista de ficheros alojados en la ruta Recursos/Servidor Lo repartimos segun su privacidad y a continuacion devolvemos al cliente los array con las
					  caracteristicas de los documentos segun el tipo de confidencialidad
					 */
					File almacenServidor = new File("Recursos/Servidor");
					File[] ficheros = almacenServidor.listFiles();
					for (int i = 0; i < ficheros.length; i++) {
						if (ficheros[i].getName().endsWith(".params"))
							continue;
						if (ficheros[i].getName().endsWith(".cif")) {
							Scanner fichero = new Scanner(new File("Recursos/Servidor/" + ficheros[i].getName()));
							String idPropietario = ficheros[i].getName().split("_")[1].split("\\.")[0];
							fichero.nextLine();
							String nombreDoc = fichero.nextLine();
							int idRegistro = Integer.parseInt(fichero.nextLine());
							String selloTemp = fichero.nextLine();
							if (getIdPropietario(solicitud.getCertAuthC()).equals(idPropietario)) {
								ListaDocPrivados.add("idPropietario: "+ idPropietario +" - NombreDoc: " + nombreDoc + " - IdRegistro: " + idRegistro
										+ " - SelloTemporal: " + selloTemp);
							}
						} else {
							Scanner fichero = new Scanner(new File("Recursos/Servidor/" + ficheros[i].getName()));
							System.out.println("Recursos/Servidor/" + ficheros[i].getName());
							String idPropietario = ficheros[i].getName().split("_")[1].split("\\.")[0];
							fichero.nextLine();
							String nombreDoc = fichero.nextLine();
							int idRegistro = Integer.parseInt(fichero.nextLine());
							String selloTemp = fichero.nextLine();
							ListaDocPublicos.add("idPropietario: " + idPropietario + " - NombreDoc: " + nombreDoc + " - IdRegistro: " + idRegistro
									+ " - SelloTemporal: " + selloTemp);
						}
					}

					// Enviamos al cliente la informacion solicitada acerca de la lista de documentos en el objeto respuesta

					System.out.println(
							"Recuperacion de listado de documentos correcta.\nSe procede al envio de estas al cliente");

					// Formamos el objeto que vamos a enviar

					respuesta = new Peticion();
					respuesta.setListaDocPublicos(ListaDocPublicos);
					respuesta.setListaDocPrivados(ListaDocPrivados);
					out.writeObject(respuesta);
					System.out.println("Envio correcto");
					break;
				}
			}
		} catch (IOException e) {
			//e.printStackTrace();
			System.out.println("Conexion cerrada");
			this.interrupt();
		} catch (ClassNotFoundException e) {
			//e.printStackTrace();
		} catch (Exception e) {
			//e.printStackTrace();
		}
	}

	// Funcion para la solicitud de un sello temporal
	// Retorna el sello temporal obtenido del TSA o null si no se ha podido recuperar

	public static Sello_Temporal pedirSello(byte[] doc) throws Exception {

		// Declaramos las variables que vamos a emplear

		MessageDigest algorit = MessageDigest.getInstance("SHA-512");
		byte[] hash = algorit.digest(doc);
		Sello_Temporal peticion = new Sello_Temporal();
		peticion.setHashDoc(hash);

		// Creamos la conexion en el puerto 9002(que está tambien indicado en la clase TSA)

		String host = "localhost";
		int port = 9002;

		// Creamos el socket SSL

		SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		SSLSocket socket = null;
		try {
			socket = (SSLSocket) factory.createSocket(host, port);
		} catch (IOException e) {
			System.out.println("Conexion denegada por el servidor TSA");
			return null;
		}
		socket.startHandshake();

		ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
		ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

		// Realizamos la peticion al servidor TSA

		out.writeObject(peticion);

		// Recibimos la respuesta

		Sello_Temporal respuesta = (Sello_Temporal) in.readObject();
		String sello = respuesta.getSelloTemporal();

		ByteArrayOutputStream concat = new ByteArrayOutputStream();
		concat.write(hash);
		concat.write(sello.getBytes());
		byte[] verificar_TSA = concat.toByteArray();

		// La verificamos mediante la funcion secundaria verificar y en caso positivo retornamos la respuesta que nos ha enviado el TSA

		if (!verificar(verificar_TSA, respuesta.getSigTSA())) {
			System.out.println("Fallo de firma de TimeStamp");
			return null;
		} else
			return respuesta;
	}

	public static byte[] getCertFirmaS() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		KeyStore ks;
		char[] ks_password = "servidor".toCharArray();
		String ks_file = "Stores/Servidor/KS_Servidor.jce";

		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream(ks_file), ks_password);

		return ks.getCertificate("cert_dsa").getEncoded();
	}
	// Funcion que devuelve la clave publica

	public static PublicKey obtenerClavePublica() throws Exception {
		KeyStore ks;
		char[] ks_password = "servidor".toCharArray();
		String ks_file = "Stores/Servidor/KS_Servidor.jce";

		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream(ks_file), ks_password);

		return ks.getCertificate("dsa").getPublicKey();
	}

	// Funcion que devuelve la clave privada

	public static PrivateKey obtenerClavePrivada() throws Exception {
		KeyStore ks;
		char[] ks_password = "servidor".toCharArray();
		char[] key_password = "servidor".toCharArray();
		String ks_file = "Stores/Servidor/KS_Servidor.jce";

		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream(ks_file), ks_password);
		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry("dsa",
				new KeyStore.PasswordProtection(key_password));

		return pkEntry.getPrivateKey();
	}

	// Funcion encargada de la firma de un documento con su clave privada

	public static byte[] firmar(byte[] documento, PrivateKey pk)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableEntryException, InvalidKeyException, SignatureException {

		System.out.println("Se ha solicitado firma de documento");

		ByteArrayInputStream mensaje = new ByteArrayInputStream(documento);

		// Detectamos el algoritmo con el que se ha codificado la clave

		String algoritmo;
		if (pk.getAlgorithm().equalsIgnoreCase("RSA")) {
			algoritmo = "MD5withRSA";
		} else {
			algoritmo = "SHA1withDSA";
		}
		int longbloque;
		byte bloque[] = new byte[1024];
		long filesize = 0;

		// Creamos un objeto que implementa el algoritmo que le indicamos arriba

		Signature signer = Signature.getInstance(algoritmo);
		signer.initSign(pk);

		byte[] firma;

		// pasamos a firmar el documento con el algoritmo indicado

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
	// Funcion encargada de verificar el certificado de firma de un cliente

	public static boolean verificarCertFirmaC(byte[] cert) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {

		System.out.println("Verificando el certificado de clave pública del cliente");
		int again=1;
		KeyStore ks;
		char[] passphrase = "servidor".toCharArray();
		boolean good=false;
		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream("Stores/Servidor/TS_Servidor.jce"), passphrase);

		Certificate certificado = null;
		do {
		if(Thread.currentThread().getStackTrace()[2].getMethodName().equals("pedirSello")) {
			System.out.println("sello");
			certificado = ks.getCertificate("cert_tsa");
		}
		else {
			if(again==1)certificado = ks.getCertificate("cert_cliente_key_dsa");
			else certificado = ks.getCertificate("cert_cliente_key_rsa");
		}
		/*for(int i = 0 ; i<cert.length; i++) {
			System.out.print(cert[i]);
		}

			for(int i = 0 ; i<certificado.getEncoded().length; i++) {
				System.out.print(certificado.getEncoded()[i]);
			}*/
		try {
			if(Arrays.equals(certificado.getEncoded(),cert)) good=true;
		} catch (NullPointerException e) {
			if(again==1) System.out.println("No se ha introducido el certificado de clave DSA en el TrustStore del Servidor");
			if(again==2) System.out.println("No se ha introducido el certificado de clave RSA en el TrustStore del Servidor");
		}
		again++;
		}while(again==2);
		if(good)return true;
		else return false;
	}

	// Funcion encargada de verificar la autenticidad de un documento

	public static boolean verificar(byte[] doc, byte[] firma) throws Exception {
		boolean good = false;
		System.out.println("Verificando la firma del cliente");
		int again=1;
		KeyStore ks;
		char[] passphrase = "servidor".toCharArray();

		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream("Stores/Servidor/TS_Servidor.jce"), passphrase);

		Certificate certificado=null;
		do {
		if (Thread.currentThread().getStackTrace()[2].getMethodName().equals("pedirSello")) {
			certificado = ks.getCertificate("cert_tsa");
		} else {
			if(again==1)certificado = ks.getCertificate("cert_cliente_key_dsa");
			else certificado = ks.getCertificate("cert_cliente_key_rsa");
		}
		PublicKey clavePublica;
		try {
			clavePublica = certificado.getPublicKey();

		System.out.println("Documento: ");
		for (int i = 0; i < 50; i++) {
			System.out.print(doc[i] + " ");
		}
		System.out.println();
		System.out.println("Firma: ");
		for (int i = 0; i < firma.length; i++) {
			System.out.print(firma[i] + " ");
		}
		System.out.println();
		ByteArrayInputStream firmaV = new ByteArrayInputStream(doc);

		String algoritmo;
		byte bloque[] = new byte[1024];
		int longbloque;

		if (clavePublica.getAlgorithm().equalsIgnoreCase("RSA")) {
			algoritmo = "MD5withRSA";
		} else {
			algoritmo = "SHA1withDSA";
		}

		Signature verifier = Signature.getInstance(algoritmo);
		verifier.initVerify(clavePublica);

		while ((longbloque = firmaV.read(bloque)) > 0) {
			verifier.update(bloque, 0, longbloque);
		}

		firmaV.close();
		if (verifier.verify(firma)) {
			good=true;
			/*System.out.println("Firma CORRECTA");
			return true;*/
		}
		} catch (NullPointerException e) {
			if(again==1) System.out.println("No se ha introducido el certificado de clave DSA en el TrustStore del Servidor");
			if(again==2) System.out.println("No se ha introducido el certificado de clave RSA en el TrustStore del Servidor");

		}

		again++;
	}while(again==2);
		if(good) {
			System.out.println("Firma CORRECTA");
			return true;
		}
		else {
			System.out.println("Firma INCORRECTA");
			return false;
		}
	}

	// Funcion encargada de devolver un idPropietario dado un certificado de autenticacion
	private String getIdPropietario(byte[] cert) throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyStoreException {
		KeyStore ks;
		char[] passphrase = "servidor".toCharArray();
		String propietario="";
		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream("Stores/Servidor/TS_Servidor.jce"), passphrase);

		Enumeration<String> en = ks.aliases();
		while(en.hasMoreElements()) {
			String thisone=en.nextElement();
			if(Arrays.equals(ks.getCertificate(thisone).getEncoded(),cert)) {
				propietario = ((X509Certificate) ks.getCertificate(thisone)).getSubjectDN().getName().substring(3, ((X509Certificate)ks.getCertificate(thisone)).getSubjectDN().getName().lastIndexOf(","));
			}
		}
		return propietario;
	}

	// Funcion encargada de cifrar un documento(su array de bytes) apartir del algoritmo indicado por parametros

	private byte[] cifrarDocumento(String nombreDoc, byte[] documento, String algoritmo) throws KeyStoreException,
			IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		KeyStore ks;
		char[] password = "servidor".toCharArray();
		char[] passphrase = "servidor".toCharArray();

		FileOutputStream fparametros = new FileOutputStream("Recursos/Servidor/" + nombreDoc + ".params");

		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream("Stores/Servidor/KS_Servidor.jce"), passphrase);

		String provider = "SunJCE";
		byte bloqueclaro[] = new byte[2024];
		byte bloquecifrado[];
		String transformacion;
		int longclave = 128;
		int longbloque;
		KeyStore.SecretKeyEntry ksEntry;

		if (algoritmo.equals("AES")) {
			transformacion = "/CBC/PKCS5Padding";
			ksEntry = (KeyStore.SecretKeyEntry) ks.getEntry("cifrado_aes", new KeyStore.PasswordProtection(password));
		} else {
			transformacion = "";
			ksEntry = (KeyStore.SecretKeyEntry) ks.getEntry("cifrado_arcfour",
					new KeyStore.PasswordProtection(password));
		}
		SecretKey key = ksEntry.getSecretKey();

		System.out.println("Cifrando documento: " + algoritmo + "-" + longclave);
		Cipher cifrador = Cipher.getInstance(algoritmo + transformacion);
		cifrador.init(Cipher.ENCRYPT_MODE, key);
		ByteArrayInputStream textoclaro = new ByteArrayInputStream(documento);
		ByteArrayOutputStream textocifrado = new ByteArrayOutputStream();

		while ((longbloque = textoclaro.read(bloqueclaro)) > 0) {
			bloquecifrado = cifrador.update(bloqueclaro, 0, longbloque);
			textocifrado.write(bloquecifrado);
		}
		bloquecifrado = cifrador.doFinal();
		textocifrado.write(bloquecifrado);
		System.out.println("Documento cifrado> " + algoritmo + "-" + longclave + " Proveedor: " + provider);
		textocifrado.close();
		textoclaro.close();

		if (provider.equals("SunJCE") && (algoritmo.equals("AES") || algoritmo.equals("Blowfish")
				|| algoritmo.equals("DES") || algoritmo.equals("DESede") || algoritmo.equals("DiffieHellman")
				|| algoritmo.equals("OAEP") || algoritmo.equals("PBEWithMD5AndDES")
				|| algoritmo.equals("PBEWithMD5AndTripleDES") || algoritmo.equals("PBEWithSHA1AndDESede")
				|| algoritmo.equals("PBEWithSHA1AndRC2_40") || algoritmo.equals("RC2"))) {
			AlgorithmParameters param = AlgorithmParameters.getInstance(algoritmo);
			param = cifrador.getParameters();

			byte[] paramSerializados = param.getEncoded();
			fparametros.write(paramSerializados);
			fparametros.flush();
			fparametros.close();
		}
		return textocifrado.toByteArray();
	}

	/*
	 * Funcion encargada de hacer el camino inverso a la funcion
	 * cifrarDocumento. Recibe el array de bytes del documento cifrado y el
	 * algoritmo con el que se ha llevado a cabo y se recupera el documento
	 * original en un array de bytes
	 */

	private byte[] descifrarDocumento(String nombreDoc, byte[] documentoCifrado, String algoritmo) throws Exception {

		System.out.println("Se ha solicitado descifrar el documento");

		KeyStore ks;
		char[] password = "servidor".toCharArray();
		char[] passphrase = "servidor".toCharArray();

		FileInputStream fparametros = new FileInputStream("Recursos/Servidor/" + nombreDoc + ".params");

		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream("Stores/Servidor/KS_Servidor.jce"), passphrase);

		String provider = "SunJCE";
		byte bloqueclaro[];
		byte bloquecifrado[] = new byte[1024];
		String transformacion;
		int longclave = 128;
		int longbloque;
		KeyStore.SecretKeyEntry ksEntry;

		if (algoritmo.equals("AES")) {
			transformacion = "/CBC/PKCS5Padding";
			ksEntry = (KeyStore.SecretKeyEntry) ks.getEntry("cifrado_aes", new KeyStore.PasswordProtection(password));
		} else {
			transformacion = "";
			ksEntry = (KeyStore.SecretKeyEntry) ks.getEntry("cifrado_arcfour",
					new KeyStore.PasswordProtection(password));
		}
		SecretKey key = ksEntry.getSecretKey();

		System.out.println("Descifrando documento: " + algoritmo + "-" + longclave);

		Cipher descifrador = Cipher.getInstance(algoritmo + transformacion, provider);

		// Leer los parametros si el algoritmo soporta parametros

		if (provider.equals("SunJCE") && (algoritmo.equals("AES") || algoritmo.equals("Blowfish")
				|| algoritmo.equals("DES") || algoritmo.equals("DESede") || algoritmo.equals("DiffieHellman")
				|| algoritmo.equals("OAEP") || algoritmo.equals("PBEWithMD5AndDES")
				|| algoritmo.equals("PBEWithMD5AndTripleDES") || algoritmo.equals("PBEWithSHA1AndDESede")
				|| algoritmo.equals("PBEWithSHA1AndRC2_40") || algoritmo.equals("RC2"))) {
			AlgorithmParameters params = AlgorithmParameters.getInstance(algoritmo, provider);
			byte[] paramSerializados = new byte[fparametros.available()];

			fparametros.read(paramSerializados);
			params.init(paramSerializados);

			descifrador.init(Cipher.DECRYPT_MODE, key, params);
		} else {
			descifrador.init(Cipher.DECRYPT_MODE, key);
		}

		ByteArrayInputStream textocifrado = new ByteArrayInputStream(documentoCifrado);
		ByteArrayOutputStream textoclaro = new ByteArrayOutputStream();

		while ((longbloque = textocifrado.read(bloquecifrado)) > 0) {
			bloqueclaro = descifrador.update(bloquecifrado, 0, longbloque);
			textoclaro.write(bloqueclaro);
		}

		bloqueclaro = descifrador.doFinal();

		System.out.println("Documento descifrado con exito");
		textoclaro.write(bloqueclaro);
		textocifrado.close();
		textoclaro.close();
		return textoclaro.toByteArray();

	}
}
