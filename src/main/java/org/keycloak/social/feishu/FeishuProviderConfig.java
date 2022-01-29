package org.keycloak.social.feishu;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

import java.io.Serializable;

/**
 * @author Jinxin
 * created at 2022/1/20 10:39
 **/
public class FeishuProviderConfig extends OAuth2IdentityProviderConfig implements Serializable {

    public FeishuProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public FeishuProviderConfig() {
    }


}
