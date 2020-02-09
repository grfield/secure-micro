import io.fusionauth.jwt.Signer;
import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.rsa.RSASigner;
import io.fusionauth.jwt.rsa.RSAVerifier;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

public class Main {
    public static void main(String[] args) throws Exception {
        System.out.println("Creating JWT token");
        // Build an RSA signer using a SHA-256 hash
        Signer signer = RSASigner.newSHA256Signer(
                new String(Files.readAllBytes(Paths.get("private_key.pem"))));

        // Build a new JWT with an issuer(iss), issued at(iat), subject(sub) and expiration(exp)
        JWT jwt = new JWT().setIssuer("www.acme.com")
                .setIssuedAt(ZonedDateTime.now(ZoneOffset.UTC))
                .setSubject("f1e33ab3-027f-47c5-bb07-8dd8ab37a2d3")
                .setExpiration(ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(60));

        // Sign and encode the JWT to a JSON string representation
        String encodedJWT = JWT.getEncoder().encode(jwt, signer);

        System.out.println(encodedJWT + "\n");

        System.out.println("Decoding JWT token");

        // Build an RSA verifier using an RSA Public Key
        Verifier verifier = RSAVerifier.newVerifier(Paths.get("public_key.pem"));

        // Verify and decode the encoded string JWT to a rich object
        jwt = JWT.getDecoder().decode(encodedJWT, verifier);

        System.out.println(jwt.toString());
    }
}
