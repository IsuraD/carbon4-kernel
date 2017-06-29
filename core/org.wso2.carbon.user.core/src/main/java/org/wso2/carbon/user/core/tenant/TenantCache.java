package org.wso2.carbon.user.core.tenant;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.Caching;

public class TenantCache {

    public static final String TENANT_CACHE_MANAGER = "TENANT_CACHE_MANAGER";
    public static final String TENANT_CACHE = "TENANT_CACHE";
    private static Log log = LogFactory.getLog(TenantCache.class);

    private static TenantCache tenantCache = new TenantCache();

    private TenantCache() {
    }

    /**
     * Gets a new instance of TenantCache.
     *
     * @return A new instance of TenantCache.
     */
    public synchronized static TenantCache getInstance() {
        return tenantCache;
    }

    /**
     * Getting existing cache if the cache available, else returns a newly created cache.
     * This logic handles by javax.cache implementation
     */
    private <T> Cache<TenantIdKey, T> getTenantCache() {
        Cache<TenantIdKey, T> cache = null;
        CacheManager cacheManager = Caching.getCacheManagerFactory().getCacheManager(TENANT_CACHE_MANAGER);
        cache = cacheManager.getCache(TENANT_CACHE);
        return cache;
    }

    /**
     * Add a cache entry.
     * Tenant
     *
     * @param key   Key which cache entry is indexed.
     * @param entry Actual object where cache entry is placed.
     */
    public <T> void addToCache(TenantIdKey key, T entry) {

        PrivilegedCarbonContext.startTenantFlow();

        try {
            PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            carbonContext.setTenantId(MultitenantConstants.SUPER_TENANT_ID);
            carbonContext.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

            // Element already in the cache. Remove it first
            clearCacheEntry(key);

            Cache<TenantIdKey, T> cache = getTenantCache();
            if (cache != null) {
                cache.put(key, entry);
                if (log.isDebugEnabled()) {
                    log.debug(TENANT_CACHE + " which is under " + TENANT_CACHE_MANAGER + ", added the entry : " + entry
                            + " for the key : " + key + " successfully");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting the cache : " + TENANT_CACHE + " which is under " +
                            TENANT_CACHE_MANAGER);
                }
            }
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    /**
     * Retrieves a cache entry.
     *
     * @param key CacheKey
     * @return Cached entry if the key presents, else returns null.
     */
    public <T> T getValueFromCache(TenantIdKey key) {

        PrivilegedCarbonContext.startTenantFlow();

        try {
            PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            carbonContext.setTenantId(MultitenantConstants.SUPER_TENANT_ID);
            carbonContext.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

            Cache<TenantIdKey, T> cache = getTenantCache();
            if (cache != null) {
                if (cache.containsKey(key)) {
                    T entry = cache.get(key);
                    if (log.isDebugEnabled()) {
                        log.debug(TENANT_CACHE + " which is under " + TENANT_CACHE_MANAGER + ", found the entry : " +
                                entry + " for the key : " + key + " successfully");
                    }
                    return entry;
                }
                if (log.isDebugEnabled()) {
                    log.debug(TENANT_CACHE + " which is under " + TENANT_CACHE_MANAGER + ", doesn't contain the key :" +
                            " " + key);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting the cache : " + TENANT_CACHE + " which is under " +
                            TENANT_CACHE_MANAGER);
                }
            }
            return null;

        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    /**
     * Clears a cache entry.
     *
     * @param key Key to clear cache.
     */
    public void clearCacheEntry(TenantIdKey key) {

        PrivilegedCarbonContext.startTenantFlow();

        try {
            PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            carbonContext.setTenantId(MultitenantConstants.SUPER_TENANT_ID);
            carbonContext.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

            Cache<TenantIdKey, Object> cache = getTenantCache();
            if (cache != null) {
                if (cache.containsKey(key)) {
                    cache.remove(key);
                    if (log.isDebugEnabled()) {
                        log.debug(TENANT_CACHE + " which is under " + TENANT_CACHE_MANAGER + ", is removed entry for " +
                                "the key : " + key + " successfully");
                    }
                }

                if (log.isDebugEnabled()) {
                    log.debug(TENANT_CACHE + " which is under " + TENANT_CACHE_MANAGER + ", doen't contain the key : " +
                            "" + key);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting the cache : " + TENANT_CACHE + " which is under " +
                            TENANT_CACHE_MANAGER);
                }
            }

        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    /**
     * Remove everything in the cache.
     */
    public void clear() {

        PrivilegedCarbonContext.startTenantFlow();

        try {
            PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            carbonContext.setTenantId(MultitenantConstants.SUPER_TENANT_ID);
            carbonContext.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

            Cache<TenantIdKey, Object> cache = getTenantCache();
            if (cache != null) {
                cache.removeAll();
                if (log.isDebugEnabled()) {
                    log.debug(TENANT_CACHE + " which is under " + TENANT_CACHE_MANAGER + ", is cleared successfully");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Error while getting the cache : " + TENANT_CACHE + " which is under " +
                            TENANT_CACHE_MANAGER);
                }
            }

        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }


}
