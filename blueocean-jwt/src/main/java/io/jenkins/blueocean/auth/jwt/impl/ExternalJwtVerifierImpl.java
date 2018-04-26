package io.jenkins.blueocean.auth.jwt.impl;

import javax.servlet.http.HttpServletRequest;
import io.jenkins.blueocean.auth.jwt.JwtTokenVerifier;
import io.jenkins.blueocean.commons.ServiceException;
import org.acegisecurity.Authentication;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import hudson.Extension;
import hudson.model.User;
import jenkins.model.Jenkins;

/**
 * JWT Verifier for JWTs issues by services external to Jenkins, eg Dex, Google etc.
 */
@Extension
public class ExternalJwtVerifierImpl extends JwtTokenVerifier {

    private static final Logger logger = LoggerFactory.getLogger(ExternalJwtVerifierImpl.class);

    // FIXME - static hacks
    private static final HttpsJwksVerificationKeyResolver httpsJwksKeyResolver =
        new HttpsJwksVerificationKeyResolver(new HttpsJwks("http://35.189.197.59/keys"));
    private static final String[] expectedAudience = { "authproxy", "jenkins" };

    @Override
    public Authentication verify(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null;
        }
        String token = authHeader.substring("Bearer ".length());
        JsonWebStructure jws = parse(token);
        if (jws == null) {
            return null;
        }
        try {
            JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setRequireSubject() // the JWT must have a subject claim
                .setVerificationKeyResolver(httpsJwksKeyResolver).setExpectedAudience(expectedAudience)
                .setExpectedAudience(expectedAudience)
                .build(); // create the JwtConsumer instance

            try {
                JwtContext context = jwtConsumer.process(token);
                JwtClaims claims = context.getJwtClaims();

                String subject = claims.getSubject();
                if (subject.equals("anonymous")) { //if anonymous, we do not bother checking expiration
                    return Jenkins.ANONYMOUS;
                } else {
                    // If not anonymous user, get Authentication object associated with this claim
                    // We give a change to the authentication store to inspect the claims and if expired it might
                    // do cleanup of associated Authentication object for example.
                    User user = User.getById(claims.getStringClaimValue("email"), false);
                    return user == null ? null : user.impersonate();
                }

            } catch (InvalidJwtException e) {
                logger.error("Invalid JWT token: " + e.getMessage(), e);
                throw new ServiceException.UnauthorizedException("Invalid JWT token");
            } catch (MalformedClaimException e) {
                logger.error(String.format("Error reading sub header for token %s", jws.getPayload()), e);
                throw new ServiceException.UnauthorizedException("Invalid JWT token: malformed claim");
            }
        } catch (JoseException e) {
            logger.error("Error parsing JWT token: " + e.getMessage(), e);
            throw new ServiceException.UnauthorizedException("Invalid JWT Token: " + e.getMessage());
        }
    }

    private JsonWebStructure parse(String token) {
        try {
            return JsonWebStructure.fromCompactSerialization(token);
        } catch (JoseException e) {
            // token was not formed as JWT token. Probably it's a different kind of bearer token
            // some other plugins have introduced
            return null;
        }
    }

}
