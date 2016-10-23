package org.athento.nuxeo.security.util;

import org.nuxeo.ecm.platform.rendering.api.RenderingEngine;
import org.nuxeo.ecm.platform.rendering.api.ResourceLocator;
import org.nuxeo.ecm.platform.rendering.fm.FreemarkerEngine;

import java.io.File;
import java.net.URL;

/**
 * Templates helper.
 */
public class TemplatesHelper {

    protected static RenderingEngine engine;

    protected class ViewResourceLocator implements ResourceLocator {
        public File getResourceFile(String key) {
            return null;
        }

        public URL getResourceURL(String key) {
            return this.getClass().getClassLoader().getResource(key);
        }
    }

    /**
     * Get rendering engine.
     *
     * @return
     */
    public RenderingEngine getRenderingEngine() {
        if (engine == null) {
            engine = new FreemarkerEngine();
            engine.setResourceLocator(new ViewResourceLocator());
        }
        return engine;
    }

}
