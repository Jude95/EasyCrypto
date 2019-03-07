package com.jude.easy_crypto;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class ResourceLoader {

    public static URL getResource(String resource) {
        final List<ClassLoader> classLoaders = new ArrayList<ClassLoader>();
        classLoaders.add(Thread.currentThread().getContextClassLoader());
        classLoaders.add(ResourceLoader.class.getClassLoader());

        for (ClassLoader classLoader : classLoaders) {
            final URL url = getResourceWith(classLoader, resource);
            if (url != null) {
                return url;
            }
        }

        final URL systemResource = ClassLoader.getSystemResource(resource);
        if (systemResource != null) {
            return systemResource;
        } else {
            try {
                return new File(resource).toURI().toURL();
            } catch (MalformedURLException e) {
                return null;
            }
        }
    }

    private static URL getResourceWith(ClassLoader classLoader, String resource) {
        if (classLoader != null) {
            return classLoader.getResource(resource);
        }
        return null;
    }

}