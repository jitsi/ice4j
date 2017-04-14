package org.ice4j.attribute;

public interface KeysDependentAttributeContext {

    byte[] getRemoteKey(String username, String media);

    byte[] getLocalKey(String username);
}
