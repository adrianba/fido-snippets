package webauthenticator;

import com.fasterxml.jackson.annotation.JsonProperty;

public class WebAuthenticationPublicKey {

	public WebAuthenticationPublicKey(String kty, String alg, boolean ext, String n, String e) {
		this.alg = alg;
		this.e = e;
		this.ext = ext;
		this.kty = kty;
		this.n = n;
	}

	@JsonProperty("alg")
	private String alg;

	@JsonProperty("e")
	private String e;

	@JsonProperty("ext")
	private boolean ext;

	@JsonProperty("kty")
	private String kty;

	@JsonProperty("n")
	private String n;

	public String getAlg() {
		return alg;
	}

	public String getE() {
		return e;
	}

	public boolean isExt() {
		return ext;
	}

	public String getKty() {
		return kty;
	}

	public String getN() {
		return n;
	}
}