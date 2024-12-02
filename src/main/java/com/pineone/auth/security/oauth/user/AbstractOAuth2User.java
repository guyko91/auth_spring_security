package com.pineone.auth.security.oauth.user;

import java.util.Map;
import java.util.Optional;
import lombok.Getter;

@Getter
public abstract class AbstractOAuth2User {
    private final Map<String, Object> attributes;

    protected AbstractOAuth2User(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    protected String getAttribute(String[] parentKeys, String key) {
        if (parentKeys == null || parentKeys.length == 0) {
            return getAttributeWithoutDepth(key);
        }
        return getChildAttributeValue(parentKeys, key);
    }

    private String getAttributeWithoutDepth(String key) {
        return attributes.get(key) == null ? "" : String.valueOf(attributes.get(key));
    }

    private String getChildAttributeValue(String[] parentKeys, String childKey) {
        Map<String, Object> target = attributes;

        for (String parentKey : parentKeys) {
            if (target == null || !(target.get(parentKey) instanceof Map)) {
                return "";
            }
            target = (Map<String, Object>) target.get(parentKey);
        }

        return Optional.ofNullable(target.get(childKey))
            .map(String::valueOf)
            .orElse("");
    }
}
