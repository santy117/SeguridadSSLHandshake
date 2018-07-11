import java.io.Serializable;

//Implementamos la interfaz serializable para poder trabajar con tipos de datos bytes

public class Sello_Temporal implements Serializable {

	byte[] hashDoc;

	String selloTemporal;
	byte[] SigTSA;

	// Constructor

	public Sello_Temporal() {

	}

	public void setHashDoc(byte[] h) {
		hashDoc = h;
	}

	public void setSelloTemporal(String s) {
		selloTemporal = s;
	}

	public void setSigTSA(byte[] t) {
		SigTSA = t;
	}

	public byte[] getHashDoc() {
		return hashDoc;
	}

	public String getSelloTemporal() {
		return selloTemporal;
	}

	public byte[] getSigTSA() {
		return SigTSA;
	}
}