package io.jenkins.blueocean.auth.jwt.impl.external;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import hudson.Extension;
import hudson.util.FormValidation;
import jenkins.model.GlobalConfiguration;
import jenkins.model.GlobalConfigurationCategory;
import jenkins.model.Jenkins;

/**
 * Exposes the config UI to the system config page.
 */
@Extension
public final class ExternalJWTConfiguration extends GlobalConfiguration {

    private static final String DEFAULT_SSO_URI = "http://dex.sso/"; // k8s service.namespace
    private static final String[] DEFAULT_EXPECTED_AUDIENCE = { "authproxy", "jenkins" };

    private String ssoUri = DEFAULT_SSO_URI;
    private List<String> audience = Arrays.asList(DEFAULT_EXPECTED_AUDIENCE);

    private transient volatile JwtConsumer jwtConsumer;

    public ExternalJWTConfiguration() {
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

    JwtConsumer getJwtConsumer() {
        return jwtConsumer;
    }

    private void buildConsumer() {
        JwtConsumerBuilder builder = new JwtConsumerBuilder()
            .setRequireExpirationTime() // the JWT must have an expiration time
            .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
            .setRequireSubject() // the JWT must have a subject claim
            .setVerificationKeyResolver( new HttpsJwksVerificationKeyResolver(new HttpsJwks(ssoUri)));
        if (!audience.isEmpty()) {
            builder.setExpectedAudience(audience.toArray(new String[audience.size()]));
        }
        jwtConsumer = builder.build(); // create the JwtConsumer instance
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
        List<String> strings = toStringList(value);
        if (strings.isEmpty()) {
            return FormValidation.warning("No audiences are set - this will allow tokens from any application on the "
                                          + "SSO server to login.  You should not do this unless the SSO server is "
                                          + "suitable restricted (e.g. Google.com is not)");
        }
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
        List<String> values = Arrays.stream(newLineSeparatedValues.split("\r?\n"))
                                                    .map(String::trim)
                                                    .filter(line -> !line.isEmpty())
                                                    .collect(Collectors.toList());
        return values;
    }
}
