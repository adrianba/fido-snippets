package webauthenticator;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class WebAuthenticator {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	public static boolean validateSignature(WebAuthenticationPublicKey pk, String clientData, String authnrData, String signature, String challenge) {
		try {
			byte[] c = Base64.getUrlDecoder().decode(clientData);
			byte[] a = Base64.getUrlDecoder().decode(authnrData);
			byte[] s = Base64.getUrlDecoder().decode(signature);

			String cc = new String(c, StandardCharsets.US_ASCII);
			cc = cc.replace("\0","").trim();

			JsonNode j = OBJECT_MAPPER.readValue(cc, JsonNode.class);

			if(!j.get("challenge").asText().equals(challenge)) {
				return false;
			}

			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] h = digest.digest(c);

			RSAPublicKeySpec spec = new RSAPublicKeySpec(
				new BigInteger(1, Base64.getUrlDecoder().decode(pk.getN())),
				new BigInteger(1, Base64.getUrlDecoder().decode(pk.getE()))
			);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			PublicKey pub = factory.generatePublic(spec);
			Signature verifier = Signature.getInstance("SHA256withRSA");
			verifier.initVerify(pub);
			verifier.update(a);
			verifier.update(h);
			return verifier.verify(s);
		} catch (Exception e) {
			return false;
		}
	}

}
