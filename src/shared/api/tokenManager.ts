/**
 * In-Memory Token Manager
 * 
 * Security: Tokens are stored in closure, not in localStorage or sessionStorage.
 * This prevents XSS attacks from accessing tokens.
 */

type TokenType = 'access' | 'refresh';

interface TokenStore {
    accessToken: string | null;
    refreshToken: string | null;
}

// Closure-based token storage - not accessible from window object
const tokenStore: TokenStore = {
    accessToken: null,
    refreshToken: null,
};

// Queue for requests waiting for token refresh
let isRefreshing = false;
let refreshSubscribers: Array<(token: string) => void> = [];

/**
 * Subscribe to token refresh completion
 */
const subscribeToTokenRefresh = (callback: (token: string) => void): void => {
    refreshSubscribers.push(callback);
};

/**
 * Notify all subscribers when refresh is complete
 */
const onTokenRefreshed = (token: string): void => {
    refreshSubscribers.forEach((callback) => callback(token));
    refreshSubscribers = [];
};

/**
 * Token Manager API
 */
export const tokenManager = {
    /**
     * Get access token from memory
     */
    getAccessToken: (): string | null => {
        return tokenStore.accessToken;
    },

    /**
     * Get refresh token from memory
     */
    getRefreshToken: (): string | null => {
        return tokenStore.refreshToken;
    },

    /**
     * Set tokens in memory
     */
    setTokens: (accessToken: string, refreshToken?: string): void => {
        tokenStore.accessToken = accessToken;
        if (refreshToken) {
            tokenStore.refreshToken = refreshToken;
        }
    },

    /**
     * Clear all tokens from memory
     */
    clearTokens: (): void => {
        tokenStore.accessToken = null;
        tokenStore.refreshToken = null;
    },

    /**
     * Check if user has valid access token
     */
    hasAccessToken: (): boolean => {
        return tokenStore.accessToken !== null;
    },

    /**
     * Get refresh state
     */
    isRefreshing: (): boolean => {
        return isRefreshing;
    },

    /**
     * Set refresh state
     */
    setRefreshing: (state: boolean): void => {
        isRefreshing = state;
    },

    /**
     * Subscribe to token refresh
     */
    subscribeToRefresh: subscribeToTokenRefresh,

    /**
     * Notify refresh complete
     */
    notifyRefreshComplete: onTokenRefreshed,
};

export type { TokenType, TokenStore };
