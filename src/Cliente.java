import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.*;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.Random;

public class Cliente {
	public static void main(String[] args) throws Exception {

		Scanner teclado = new Scanner(System.in);
		boolean sigue=true;
		// pasamos los argumentos de entrada a una funcion secundaria que se encarga de su extraccion y la asignacion de las keyStore/trustStore

		defineKeyStores(args);

		String host = "localhost";

		// se utilizara en puerto 9001 para la realizacion de la conexion entre cliente y servidor

		int port = 9001;

		// declaramos el ssl socket

		SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		SSLSocket socket = null;
		try {
			socket = (SSLSocket) factory.createSocket(host, port);
		} catch (IOException e) {
			//e.printStackTrace();
			System.out.println("Conexion denegada creando socket");
			return;
		}

		System.out.println("Socket creado con exito\nSuites de cifrado disponibles:"); 
		SSLContext context = SSLContext.getDefault();
		SSLSocketFactory sf = context.getSocketFactory();
		
		HashMap<Integer,String> cs = new HashMap<Integer,String>();
		// Mostramos por pantalla las suites de cifrado disponibles y damos la opcion de seleccionar una
		int entero=1;
		String[] cipherSuites = sf.getSupportedCipherSuites();
		for (int i = 0; i < cipherSuites.length; i++) {
			if (cipherSuites[i].startsWith("SSL")) {
				System.out.println(entero+".- "+cipherSuites[i]);
				cs.put(entero,cipherSuites[i]);
				entero++;
			}
		}
		System.out.println("Introduzca una de las suites ofertadas:");
		String suite[] = new String[1];
		int number = Integer.parseInt(teclado.nextLine());
		suite[0]=cs.get(number);
		socket.setEnabledCipherSuites(suite);
		// Comenzamos el protocolo Handshake para la eleccion de los parametros de la comunicacion

		try {
			System.out.println("Intento de Handshake SSL, espere");
			socket.startHandshake();
		} catch (SSLHandshakeException e) {
			//e.printStackTrace();
			System.out.println("Suite SSL no aceptada");
			return;
		}
		System.out.println("Suite SSL aceptada");

		// Declaramos los objetos que nos van a servir para la recepcion y el envio de datos

		ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
		ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

		//Scanner fich_ejecucion = new Scanner(new File(args[4]));
		//while (fich_ejecucion.hasNextLine()) {
			//String comando = fich_ejecucion.nextLine();
			//if (comando.startsWith("*"))
				//continue;
		
		while(sigue) {
			Peticion peticion;
			Peticion respuesta;
			System.out.println("Introduce la operacion a realizar:");
			System.out.println("1.- Registrar documento");
			System.out.println("2.- Recuperar documento");
			System.out.println("3.- Listar documentos");
			System.out.println("(Cualquier otra opción finalizará la ejecución del programa)");

			switch (Integer.parseInt(teclado.nextLine())) {
			// Opcion registrar documento

			case 1:
				System.out.println("Se ha solicitado registro de documento");
				System.out.println("Introduzca el nombre del propietario que va a registrar el certificado:");
				String idProp = teclado.nextLine();
				// creamos un objeto de la clase peticion indicandole la operacion a realizar y le proporcionamos los atributos necesarios para llevarla a cabo
				System.out.println("Introduzca ahora el nombre del documento que quiere registrar (extension incluida):");
				String nombreDoc = teclado.nextLine();
				System.out.println("Introduzca, por último, si quiere que el documento sea PUBLICO o PRIVADO");
				String confidencialidad = teclado.nextLine();
				peticion = new Peticion("REGISTRAR_DOCUMENTO");

				peticion.setIdPropietario(idProp);
				peticion.setNombreDoc(nombreDoc);
				peticion.setConfidencialidad(confidencialidad);
				System.out.println("Usuario: " + peticion.getIdPropietario() + ", para el documento: "
						+ peticion.getNombreDoc() + " con confidencialidad: " + peticion.getConfidencialidad());

				// Recuperamos los bytes del fichero(imagen) que hemos indicado que queremos transferir

				byte[] doc;
				doc = getBytes("Recursos/Cliente/" + nombreDoc);
				peticion.setDocumento(doc);
				String alg;
				// Mediante la funcion firmar(byte[],PrivateKey), con la clave privada, firmamos el documento identificando que proviene de nuestro cliente
				do{
					System.out.println("¿Firmar con clave RSA o DSA? (Escribir literalmente rsa o dsa)");
					alg=teclado.nextLine();
				}while(!alg.equals("rsa") && !alg.equals("dsa"));
				byte[] firma = firmar(doc, obtenerClavePrivada(alg));
				peticion.setFirmaDoc(firma);
				
				byte[] certFirmaC = getCertFirmaC(alg);
				peticion.setCertFirmaC(certFirmaC);
				// Anadimos al buffer de salida el objeto peticion con los atributos cubiertos en las lineas anteriores

				System.out.println(
						"El procedimiento de creacion para el envio del documento ha concluido con exito. Se procede a enviar.");
				out.writeObject(peticion);
				System.out.println("Esperando respuesta del servidor");

				// Recuperamos los datos del servidor en los que nos indica la id con la que se ha registrado el documento, el sello temporal y el sigTSA

				respuesta = (Peticion) in.readObject();
				if(respuesta.getNError()==1) {
					System.out.println("El certificado de la firma del cliente no ha sido correctamente verificado en el servidor");
					break;
				}
				
				if(respuesta.getNError()==2) {
					System.out.println("La firma del cliente no ha sido correctamente verificada en el servidor");
					break;
				}
				ByteArrayOutputStream concat = new ByteArrayOutputStream();
				concat.write((byte) respuesta.getIdRegistro());
				concat.write(respuesta.getSelloTemporal().getSelloTemporal().getBytes());
				concat.write(respuesta.getSelloTemporal().getSigTSA());
				concat.write(doc);
				concat.write(firma);
				byte[] firmar_cliente = concat.toByteArray();
				concat.close();

				// Ahora verificamos si el documento ha sido registrado en el servidor correctamente o si ha habido algun fallo en la firma
				if (!verificarCertFirmaS(respuesta.getCertFirmaS())) {
					System.out.println("CERTIFICADO DE REGISTRADOR INCORRECTO");
					break;
				}
				else System.out.println("Certificado correcto.");
				if (verificar(firmar_cliente, respuesta.getSigRD())) {
					MessageDigest algorit = MessageDigest.getInstance("SHA-512");
					byte[] hash = algorit.digest(doc);
					if (verificar_sello(hash, respuesta.getSelloTemporal())) {
						System.out.println("El documento ha sido registrado correctamente");
						FileOutputStream escribir_hash = new FileOutputStream(
								"Recursos/Cliente/" + nombreDoc.split("\\.")[0] + ".hash");
						escribir_hash.write(hash);
						escribir_hash.close();
						System.out.println("El hash es:");
						for (int i = 0; i < 30; i++) {
							System.out.print(hash[i] + " ");
						}
						System.out.println();
						new File("Recursos/Cliente/" + nombreDoc).delete();
					} else
						System.out.println("Ha ocurrido un fallo de firma de TimeStamp.");
				}

				break;
			case 2:

				// Opcion recuperar documento

				System.out.println("Se ha solicitado recuperacion de documento");

				// creamos un objeto de la clase peticion indicandole la operacion a realizar y le proporcionamos los atributos necesarios para llevarla a cabo
				System.out.println("Introduzca el nombre del propietario del documento:");
				String idPropietario = teclado.nextLine();
				System.out.println("Introduzca el identificador de registro del documento a recuperar:");
				String idReg = teclado.nextLine();
				peticion = new Peticion("RECUPERAR_DOCUMENTO");
				peticion.setCertAuthC(getCertAuth(idPropietario));//Aqui deberia enviar certificado de autenticacion 
				peticion.setIdRegistro(Integer.parseInt(idReg));
				out.writeObject(peticion);

				System.out.println("La solicitud se ha enviado con exito");
				System.out.println("Esperando respuesta del servidor");

				// Esperamos la respuesta del servidor y extraemos de ella los datos que identifican la id del registro, el sello temporal y la firma

				respuesta = (Peticion) in.readObject();
				
				if(respuesta.getNError()==3) {
					System.out.println("El nombre solicitado no coincide con ningún documento almacenado en el servidor.");
					break;
				}
				
				if(respuesta.getNError()==4) {
					System.out.println("El acceso a este documento no está permitido para el usuario.");
					break;
				}
				
				ByteArrayOutputStream concatn = new ByteArrayOutputStream();
				concatn.write((byte) respuesta.getIdRegistro());
				concatn.write(respuesta.getSelloTemporal().getSelloTemporal().getBytes());
				concatn.write(respuesta.getSelloTemporal().getSigTSA());
				concatn.write(respuesta.getDocumento());
				concatn.write(respuesta.getFirmaDoc());
				byte[] firma_cliente = concatn.toByteArray();
				concatn.close();
				
				if (!verificarCertFirmaS(respuesta.getCertFirmaS())) {
					System.out.println("CERTIFICADO DE REGISTRADOR INCORRECTO");
					break;
				}
				// verificamos si la firma coincide y en caso afirmativo procedemos a almacenar el fichero en el cliente

				if (!verificar(firma_cliente, respuesta.getSigRD())) {
					System.out.println("Ha ocurrido un fallo de firma registrador");
					break;
				} else {
					MessageDigest algor = MessageDigest.getInstance("SHA-512");
					byte[] hash_rec = algor.digest(respuesta.getDocumento());
					if (Arrays.equals(hash_rec,
							getBytes("Recursos/Cliente/" + respuesta.getNombreDoc().split("\\.")[0] + ".hash"))) {
						System.out.println("El documento se ha recuperado correctamente. Numero de registro:"
								+ respuesta.getIdRegistro() + " y sello temporal "
								+ respuesta.getSelloTemporal().getSelloTemporal().toString());
						FileOutputStream fos = new FileOutputStream(
								new File("Recursos/Cliente/" + respuesta.getNombreDoc()));
						fos.write(respuesta.getDocumento());
						fos.close();
						System.out.println("El documento se ha guardado correctamente");
					} else {
						System.out.println(
								"El documento no se ha podido guardar correctamente. El documento ha sido alterado por el registrador");
					}
				}

				break;
			case 3:

				// Opcion listar documentos

				System.out.println("Se ha solicitado presentar lista de documentos");

				// creamos un objeto de la clase peticion indicandole la operacion a realizar y le proporcionamos los atributos necesarios para llevarla a cabo que le introdujimos por parametros
				
				peticion = new Peticion("LISTAR_DOCUMENTOS");
				System.out.println("Introduzca el nombre del propietario cuyos ficheros quiere listar:");
				String idP = teclado.nextLine();
				peticion.setCertAuthC(getCertAuth(idP));
				out.writeObject(peticion);

				System.out.println("Se ha realizado la peticion");
				System.out.println("Esperando respuesta del servidor");
				respuesta = (Peticion) in.readObject();

				// Recuperamos para dos arraylist los documentos listados(tanto publicos como privados)

				ArrayList<String> ListaDocPublicos = respuesta.getListaDocPublicos();
				ArrayList<String> ListaDocPrivados = respuesta.getListaDocPrivados();

				// Mostramos por pantalla la lista de documentos

				System.out.println("Lista de documentos disponibles:");
				System.out.println("Privados: ");
				for (int i = 0; i < ListaDocPrivados.size(); i++) {
					System.out.println(ListaDocPrivados.get(i));
				}
				System.out.println("Públicos: ");
				for (int i = 0; i < ListaDocPublicos.size(); i++) {
					System.out.println(ListaDocPublicos.get(i));
				}
				break;
			
			default:
				System.out.println("Ha elegido salir del cliente");
				sigue=false;
				break;	
			/*default:

				// En caso de que la opcion leida del fichero no corresponda con ninguna opcion disponible
				System.out.println("Introduzca un comando valido: REGISTRAR_DOCUMENTO / RECUPERAR_DOCUMENTO / LISTAR_DOCUMENTOS / SALIR");
				break;*/
			}
		}
	}
	
	//Funcion que verifica el certificado de clave publica del cifrador
	
	private static boolean verificarCertFirmaS(byte[] cert) throws Exception{
		
		System.out.println("Verificando el certificado de clave pública del servidor");
		int again=1;
		boolean good=false;
		KeyStore ks;
		char[] passphrase = "cliente".toCharArray();
	
		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream("Stores/Cliente/TS_Cliente.jce"), passphrase);
		do {
		Certificate certificado=null;
	
		if(Thread.currentThread().getStackTrace()[2].getMethodName().equals("pedirSello"))
			certificado = ks.getCertificate("cert_tsa");
		else {
			if(again==1)certificado = ks.getCertificate("cert_servidor_key_dsa");
			else certificado = ks.getCertificate("cert_servidor_key_rsa");
		}
			/*for(int i = 0 ; i<cert.length; i++) {
			System.out.print(cert[i]);
		}
		System.out.println();
		for(int i = 0 ; i<certificado.getEncoded().length; i++) {
			System.out.print(certificado.getEncoded()[i]);
		}*/
		try {
			if(Arrays.equals(certificado.getEncoded(),cert)) good=true;
		} catch (NullPointerException e) {
			if(again==1) System.out.println("No se halla el certificado de la clave DSA en el TrustStore del cliente.");
			else System.out.println("No se halla el certificado de la clave RSA en el TrustStore del cliente.");
		}
		again++;
		}while(again==2);
		return good;
	}
	
	private static boolean verificar_sello(byte[] hash, Sello_Temporal sello) throws Exception {
		String selloStr = sello.getSelloTemporal();
		ByteArrayOutputStream concat = new ByteArrayOutputStream();
		concat.write(hash);
		concat.write(selloStr.getBytes());
		byte[] verificar_sello = concat.toByteArray();
		concat.close();
		if (!verificar(verificar_sello, sello.getSigTSA())) {
			return false;
		} else
			return true;
	}

	// Funcion encargada de devolver un array de bytes con el contenido del documento(en este caso una imagen)
	// Le proporcionamos la ruta al documento a transformar

	private static byte[] getBytes(String rutaDocumento) throws IOException {

		System.out.println("Leyendo el archivo: " + rutaDocumento);
		File f = new File(rutaDocumento);

		if (!f.exists()) {
			throw new IOException("No existe el fichero solicitado");
		}
		int length = (int) (f.length());
		if (length == 0) {
			throw new IOException("Longitud del fichero es 0 ");
		} else {
			FileInputStream fin = new FileInputStream(f);
			DataInputStream in = new DataInputStream(fin);
			byte[] bytecodes = new byte[length];
			in.readFully(bytecodes);
			System.out.println("Bytecodes obtenidos");
			in.close();
			for (int i = 0; i < 30; i++) {
				System.out.print(bytecodes[i] + " ");
			}
			System.out.println();
			return bytecodes;
		}

	}

	// Funcion que devuelve el certificado de autenticacion de un usuario dado
	public static byte[] getCertAuth(String id) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		System.out.println("Obteniendo certificado de autenticacion del cliente");
		KeyStore ks;
		char[] ks_password = "cliente".toCharArray();
		String ks_file = "Stores/Cliente/KS_Cliente.jce";

		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream(ks_file), ks_password);
		
		X509Certificate cert = (X509Certificate) ks.getCertificate("cert_cliente_rsa");
		System.out.println(cert.getSubjectDN().getName());
		if(cert.getSubjectDN().getName().substring(3, cert.getSubjectDN().getName().lastIndexOf(",")).equals(id)) {
			return cert.getEncoded();
		}
		return null;
	}
	// Funcion que se encarga de obtener el certificado de la clave publica de firma del cliente
	
	public static byte[] getCertFirmaC(String alg) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
	
		System.out.println("Obteniendo certificado de clave publica");
		KeyStore ks;
		char[] ks_password = "cliente".toCharArray();
		String ks_file = "Stores/Cliente/KS_Cliente.jce";

		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream(ks_file), ks_password);

		Certificate certPKC = ks.getCertificate("cert_"+alg);
		
		return certPKC.getEncoded();
	}
	
	// Funcion que recupera la clave publica de la store del cliente
	
	public static PublicKey obtenerClavePublica(String alg) throws Exception {
		System.out.println("Obteniendo clave publica");
		KeyStore ks;
		char[] ks_password = "cliente".toCharArray();
		String ks_file = "Stores/Cliente/KS_Cliente.jce";

		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream(ks_file), ks_password);

		PublicKey clavePublica = ks.getCertificate(alg).getPublicKey();
		System.out.println(clavePublica);

		return clavePublica;
	}

	// Funcion que recupera la clave privada de la store del cliente

	public static PrivateKey obtenerClavePrivada(String alg) throws Exception {
		System.out.println("Obteniendo clave privada");
		KeyStore ks;
		char[] ks_password = "cliente".toCharArray();
		char[] key_password = "cliente".toCharArray();
		String ks_file = "Stores/Cliente/KS_Cliente.jce";

		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream(ks_file), ks_password);
		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alg,
				new KeyStore.PasswordProtection(key_password));

		PrivateKey clavePrivada = pkEntry.getPrivateKey();
		for (int i = 0; i < 50; i++) {
			System.out.print(clavePrivada.getEncoded()[i] + " ");
		}
		System.out.println();
		return clavePrivada;
	}

	// Funcion encargada de firmar un documento con la clave privada del cliente
	// Recibe el array de bytes despues de transformar el documento y la clave privada del cliente

	public static byte[] firmar(byte[] documento, PrivateKey clavePrivada) throws Exception {
		System.out.println("Se ha solicitado firmar el documento");
		ByteArrayInputStream fmensaje = new ByteArrayInputStream(documento);
		String algoritmo;
		byte bloque[] = new byte[1024];
		int longbloque;

		if (clavePrivada.getAlgorithm().equalsIgnoreCase("RSA")) {
			algoritmo = "MD5withRSA";
		} else {
			algoritmo = "SHA1withDSA";
		}

		Signature signer = Signature.getInstance(algoritmo);
		signer.initSign(clavePrivada);
		while ((longbloque = fmensaje.read(bloque)) > 0) {
			signer.update(bloque, 0, longbloque);
		}

		byte[] firma = signer.sign();

		fmensaje.close();
		for (int i = 0; i < firma.length; i++) {
			System.out.print(firma[i] + " ");
		}
		System.out.println();
		return firma;
	}

	// Funcion que verifica si el documento pertenece a un determinado cliente, es decir, si ha sido firmada por el cliente que lo solicita
	// Recibe el array de bytes del documento transformado y el array de bytes de la firma del cliente

	public static boolean verificar(byte[] doc, byte[] firma) throws Exception {

		System.out.println("Verificando la firma del cifrador");
		int again=1;
		boolean good=false;
		KeyStore ks;
		char[] passphrase = "cliente".toCharArray();

		ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream("Stores/Cliente/TS_Cliente.jce"), passphrase);
		Certificate certificado;
		do {
		if (Thread.currentThread().getStackTrace()[2].getMethodName().equals("verificar_sello")) {
			certificado = ks.getCertificate("cert_tsa");
		} else {
			if(again==1)certificado = ks.getCertificate("cert_servidor_key_dsa");
			else certificado=ks.getCertificate("cert_servidor_key_rsa");
		}
		PublicKey clavePublica; 
		
		try {
			clavePublica=certificado.getPublicKey();

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
				//System.out.println("Firma CORRECTA");
				//return true;
			}
		} catch (NullPointerException e) {
			if(again==1) System.out.println("No se halla el certificado de la clave DSA en el TrustStore del cliente.");
			else System.out.println("No se halla el certificado de la clave RSA en el TrustStore del cliente.");
		}
		
		again++;
		}while(again==2);
		if(good) {
			System.out.println("Firma CORRECTA");
			return good;
		}else {
			System.out.println("Firma INCORRECTA");
			return false;
		}
	}

	// Funcion encargada de procesar los datos introducidos por parametros para la asignacion de las distintas variables

	private static void defineKeyStores(String[] args) {
		String raiz = "Stores/Cliente/";
		Scanner teclado = new Scanner(System.in);

		//String pass_keystore = args[1];
		//String pass_truststore = args[3];
		System.out.println("Introduce por pantalla la contraseña del KeyStore del cliente:");
		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.keyStore", raiz + args[0] + ".jce");
		System.setProperty("javax.net.ssl.keyStorePassword", teclado.nextLine());
		System.out.println("Introduce ahora la contraseña del TrustStore del cliente:");
		System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.trustStore", raiz + args[1] + ".jce");
		System.setProperty("javax.net.ssl.trustStorePassword", teclado.nextLine());
	}
}
