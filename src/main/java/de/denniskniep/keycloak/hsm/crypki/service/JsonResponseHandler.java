package de.denniskniep.keycloak.hsm.crypki.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpEntity;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.impl.client.AbstractResponseHandler;

import java.io.IOException;

public class JsonResponseHandler<T> extends AbstractResponseHandler<T> {

    private final Class<T> clazz;

    public JsonResponseHandler(Class<T> clazz) {
        this.clazz = clazz;
    }

    @Override
    public T handleEntity(HttpEntity entity) throws IOException {
        if (entity == null) {
            throw new ClientProtocolException("Response contains no content");
        }

        ObjectMapper om = new ObjectMapper();
        return om.readValue(entity.getContent(), clazz);
    }
}
