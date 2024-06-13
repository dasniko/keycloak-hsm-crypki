package de.denniskniep.keycloak.hsm.crypki;

import de.denniskniep.keycloak.hsm.keyprovider.HsmKeyProviderFactory;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.keys.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ConfigurationValidationHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

import static org.keycloak.provider.ProviderConfigProperty.LIST_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

public class CrypkiHsmKeyProviderFactory implements HsmKeyProviderFactory<CrypkiHsmKeyProvider> {

    public static final String ID = "crypki-hsm";
    private static final String HELP_TEXT = "Use keys from crypki hsm";

    String KEY_USE_KEY = "keyUse";
    ProviderConfigProperty KEY_USE_PROPERTY = new ProviderConfigProperty(KEY_USE_KEY, "Key use", "Whether the key should be used for signing or encryption.", LIST_TYPE,
            KeyUse.SIG.getSpecName(),
            new String[]{
                    KeyUse.SIG.getSpecName()
            });

    public static String ALGORITHM_KEY = "algorithm";
    ProviderConfigProperty ALGORITHM_PROPERTY = new ProviderConfigProperty(ALGORITHM_KEY, "Algorithm", "Intended algorithm for the key", "List",
            Algorithm.RS256,
            new String[]{
                    Algorithm.RS256,
                    Algorithm.RS384
            });

    public static String URL_KEY = "url";
    ProviderConfigProperty URL_PROPERTY = new ProviderConfigProperty(URL_KEY, "Url", "url to external keyprovider", STRING_TYPE, null);
    public static String NAME_KEY = "name";
    ProviderConfigProperty NAME_PROPERTY = new ProviderConfigProperty(NAME_KEY, "Name", "name of the external key", STRING_TYPE, null);

    private List<ProviderConfigProperty> configProperties;

    @Override
    public void init(Config.Scope config) {
        configProperties = ProviderConfigurationBuilder.create()
                .property(Attributes.PRIORITY_PROPERTY)
                .property(Attributes.ENABLED_PROPERTY)
                .property(Attributes.ACTIVE_PROPERTY)
                .property(KEY_USE_PROPERTY)
                .property(ALGORITHM_PROPERTY)
                .property(URL_PROPERTY)
                .property(NAME_PROPERTY)
                .build();
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) throws ComponentValidationException {
        ConfigurationValidationHelper validation = SecretKeyProviderUtils.validateConfiguration(model);
        validation.checkRequired(Attributes.KEY_USE_PROPERTY);
        validation.checkRequired(ALGORITHM_PROPERTY);
        validation.checkRequired(URL_PROPERTY);
        validation.checkRequired(NAME_PROPERTY);
        model.put(Attributes.KID_KEY, KeycloakModelUtils.generateId());
    }

    @Override
    public CrypkiHsmKeyProvider create(KeycloakSession session, ComponentModel model) {
        return new CrypkiHsmKeyProvider(session, model);
    }

    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return ID;
    }
}
