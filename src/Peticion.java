import java.util.ArrayList;
import java.io.Serializable;

//La clase Peticion la empleamos para el intercambio de datos entre el cliente y el servidor
//Implementamos la interfaz serializable para poder trabajar con tipos de datos bytes

public class Peticion implements Serializable {

	String tipo;
	int nError;
	String idPropietario;
	String nombreDoc;
	String tipoConfidencialidad;
	byte[] documento;
	byte[] firmaDoc;
	byte[] certFirmaC;
	byte[] certFirmaS;
	byte[] certAuthC;
	int idRegistro;
	Sello_Temporal selloTemporal;
	byte[] SigRD;

	ArrayList<String> ListaDocPublicos;
	ArrayList<String> ListaDocPrivados;

	public Peticion() {
		nError=0;
	}
	
	public Peticion(String t) {
		tipo = t;
		nError = 0;
	}
	
	public void setNError(int i) {
		nError=i;
	}
	
	public int getNError() {
		return nError;
	}
	public void setIdPropietario(String i) {
		idPropietario = i;
	}

	public void setNombreDoc(String n) {
		nombreDoc = n;
	}

	public void setConfidencialidad(String c) {
		tipoConfidencialidad = c;
	}

	public void setDocumento(byte[] d) {
		documento = d;
	}

	public void setFirmaDoc(byte[] f) {
		firmaDoc = f;
	}

	public void setIdRegistro(int i) {
		idRegistro = i;
	}

	public void setSelloTemporal(Sello_Temporal s) {
		selloTemporal = s;
	}

	public void setSigRD(byte[] s) {
		SigRD = s;
	}

	public void setListaDocPublicos(ArrayList<String> l) {
		ListaDocPublicos = l;
	}

	public void setListaDocPrivados(ArrayList<String> l) {
		ListaDocPrivados = l;
	}
	
	public void setCertFirmaC(byte[] s)  {
		certFirmaC = s;
	}
	
	public void setCertFirmaS(byte[] s) {
		certFirmaS = s;
	}
	
	public void setCertAuthC(byte[] s) {
		certAuthC = s;
	}
	
	public String getTipo() {
		return tipo;
	}

	public String getIdPropietario() {
		return idPropietario;
	}

	public String getNombreDoc() {
		return nombreDoc;
	}

	public String getConfidencialidad() {
		return tipoConfidencialidad;
	}

	public byte[] getDocumento() {
		return documento;
	}

	public byte[] getFirmaDoc() {
		return firmaDoc;
	}

	public int getIdRegistro() {
		return idRegistro;
	}

	public Sello_Temporal getSelloTemporal() {
		return selloTemporal;
	}

	public byte[] getSigRD() {
		return SigRD;
	}

	public ArrayList<String> getListaDocPublicos() {
		return ListaDocPublicos;
	}

	public ArrayList<String> getListaDocPrivados() {
		return ListaDocPrivados;
	}
	
	public byte[] getCertFirmaC() {
		return certFirmaC;
	}
	
	public byte[] getCertFirmaS() {
		return certFirmaS;
	}
	public byte[] getCertAuthC() {
		return certAuthC;
	}
	
}