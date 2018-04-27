package io.jenkins.blueocean.auth.jwt.impl;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import io.jenkins.blueocean.auth.jwt.JwtTokenVerifier;
import io.jenkins.blueocean.commons.ServiceException;
import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
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
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.model.User;
import hudson.util.FormValidation;
import jenkins.model.GlobalConfiguration;
import jenkins.model.GlobalConfigurationCategory;
import jenkins.model.Jenkins;

/**
 * JWT Verifier for JWTs issues by services external to Jenkins, eg Dex, Google etc.
 */
@Extension
public class ExternalJwtVerifierImpl extends JwtTokenVerifier {

    private static final Logger logger = LoggerFactory.getLogger(ExternalJwtVerifierImpl.class);

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
            final GlobalConfigurationImpl config = ExtensionList.lookupSingleton(GlobalConfigurationImpl.class);
            JwtConsumer jwtConsumer = config.getJwtConsumer();

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

    /**
     * Exposes the config UI to the system config page.
     */
    @Extension
    public static class GlobalConfigurationImpl extends GlobalConfiguration {

        private static final String DEFAULT_SSO_URI = "http://dex.sso/";
        private static final String[] DEFAULT_EXPECTED_AUDIENCE = { "authproxy", "jenkins" };

        private String ssoUri = DEFAULT_SSO_URI;
        private List<String> audience = Arrays.asList(DEFAULT_EXPECTED_AUDIENCE);

        private transient volatile JwtConsumer jwtConsumer;

        public GlobalConfigurationImpl() {
            load();
            buildConsumer();
        }

        @Override
        public GlobalConfigurationCategory getCategory() {
            return GlobalConfigurationCategory.get(GlobalConfigurationCategory.Security.class);
        }

        @Restricted(NoExternalUse.class) // public for form binding only
        @SuppressWarnings("unused")
        public String getSsoUri() {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return ssoUri;
        }

        @Restricted(NoExternalUse.class) // public for form binding only
        public List<String> getAudience() {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return audience;
        }

        private JwtConsumer getJwtConsumer() {
            return jwtConsumer;
        }

        private void buildConsumer() {
            jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setRequireSubject() // the JWT must have a subject claim
                .setVerificationKeyResolver( new HttpsJwksVerificationKeyResolver(new HttpsJwks(ssoUri)))
                .setExpectedAudience(audience.toArray(new String[audience.size()]))
                .build(); // create the JwtConsumer instance
        }

        @Restricted(NoExternalUse.class) // public for form binding only
        @SuppressWarnings("unused")
        public FormValidation doCheckSsoUri(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            try {
                URL u = new URL(value);
                return FormValidation.ok();
            } catch (MalformedURLException mUrlex) {
                return FormValidation.error(mUrlex, "The URI is not valid");
            }
        }


        @Restricted(NoExternalUse.class) // public for form binding only
        @SuppressWarnings("unused")
        public FormValidation doCheckAudience(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            // TODO what validation can we have here?
            return FormValidation.ok();
        }


        @Override
        public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            String _ssoUri;
            List<String> _audience;
            try {
                _ssoUri = json.getString("ssoUri");
                FormValidation fv = doCheckSsoUri(_ssoUri);
                if (FormValidation.Kind.ERROR == fv.kind) {
                    throw new FormException(fv.getMessage(), fv.getCause(), "ssoUri");
                }
            } catch (JSONException jex) {
                throw new FormException(jex, "ssoUri");
            }
            try {
                String rawAudience = json.getString("audience");
                FormValidation fv = doCheckAudience(rawAudience);
                if (FormValidation.Kind.ERROR == fv.kind) {
                    throw new FormException(fv.getMessage(), fv.getCause(), "audience");
                }
                _audience = toStringList(rawAudience);
            } catch (JSONException jex) {
                throw new FormException(jex, "audience");
            }
            ssoUri = _ssoUri;
            audience = _audience;
            buildConsumer();
            save();
            return true;
        }

        @Override
        public String getDisplayName() {
            return "External JWT Verifier";
        }

        @Restricted(NoExternalUse.class) // public for jelly access workaround JENKINS-27901
        public String joinWithNewLines(List<String> strArr) {
            return String.join("\n", strArr);
        }

        private static List<String> toStringList(String newLineSeparatedValues) {
            if (newLineSeparatedValues == null) {
                return null;
            }
            ArrayList<String> values = new ArrayList<>();
            for (String line : newLineSeparatedValues.split("\r?\n")) {
                line = line.trim();
                if (!line.isEmpty()) {
                    values.add(line);
                }
            }
            return values;
        }
    }
}
