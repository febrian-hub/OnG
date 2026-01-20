/**
 * Secure Axios Client
 * 
 * Features:
 * - CSRF Protection via X-XSRF-TOKEN header
 * - In-memory token management (no localStorage)
 * - Automatic token refresh on 401
 * - Secure cookie handling with credentials
 */

import axios, {
    type AxiosError,
    type AxiosInstance,
    type AxiosResponse,
    type InternalAxiosRequestConfig,
} from 'axios';
import { tokenManager } from './tokenManager';
import { API_CONFIG } from '@shared/config/api.config';

// Extended config for retry tracking
interface ExtendedAxiosRequestConfig extends InternalAxiosRequestConfig {
    _retry?: boolean;
}

/**
 * Read XSRF-TOKEN from cookies
 */
const getXsrfToken = (): string | null => {
    const match = document.cookie.match(/XSRF-TOKEN=([^;]+)/);
    return match?.[1] ? decodeURIComponent(match[1]) : null;
};

/**
 * Create secure Axios instance
 */
const createSecureClient = (): AxiosInstance => {
    const client = axios.create({
        baseURL: API_CONFIG.baseURL,
        timeout: API_CONFIG.timeout,
        withCredentials: true, // Required for httpOnly cookies
        headers: {
            'Content-Type': 'application/json',
        },
    });

    /**
     * Request Interceptor
     * - Adds Authorization header with access token
     * - Adds CSRF token to request headers
     */
    client.interceptors.request.use(
        (config: InternalAxiosRequestConfig): InternalAxiosRequestConfig => {
            // Add Authorization header if token exists
            const accessToken = tokenManager.getAccessToken();
            if (accessToken && config.headers) {
                config.headers.Authorization = `Bearer ${accessToken}`;
            }

            // Add CSRF token
            const xsrfToken = getXsrfToken();
            if (xsrfToken && config.headers) {
                config.headers['X-XSRF-TOKEN'] = xsrfToken;
            }

            return config;
        },
        (error: AxiosError) => {
            return Promise.reject(error);
        }
    );

    /**
     * Response Interceptor
     * - Handles 401 errors with automatic token refresh
     * - Queues failed requests during refresh
     */
    client.interceptors.response.use(
        (response: AxiosResponse) => response,
        async (error: AxiosError) => {
            const originalRequest = error.config as ExtendedAxiosRequestConfig | undefined;

            // If no config or already retried, reject
            if (!originalRequest) {
                return Promise.reject(error);
            }

            // Handle 401 Unauthorized
            if (error.response?.status === 401 && !originalRequest._retry) {
                // If already refreshing, queue this request
                if (tokenManager.isRefreshing()) {
                    return new Promise((resolve) => {
                        tokenManager.subscribeToRefresh((newToken: string) => {
                            if (originalRequest.headers) {
                                originalRequest.headers.Authorization = `Bearer ${newToken}`;
                            }
                            resolve(client(originalRequest));
                        });
                    });
                }

                originalRequest._retry = true;
                tokenManager.setRefreshing(true);

                try {
                    // Attempt to refresh token
                    const refreshToken = tokenManager.getRefreshToken();

                    if (!refreshToken) {
                        throw new Error('No refresh token available');
                    }

                    const response = await axios.post<{ accessToken: string; refreshToken?: string }>(
                        `${API_CONFIG.baseURL}${API_CONFIG.endpoints.refreshToken}`,
                        { refreshToken },
                        { withCredentials: true }
                    );

                    const { accessToken, refreshToken: newRefreshToken } = response.data;

                    // Update tokens
                    tokenManager.setTokens(accessToken, newRefreshToken);
                    tokenManager.setRefreshing(false);
                    tokenManager.notifyRefreshComplete(accessToken);

                    // Retry original request with new token
                    if (originalRequest.headers) {
                        originalRequest.headers.Authorization = `Bearer ${accessToken}`;
                    }

                    return client(originalRequest);
                } catch (refreshError) {
                    // Refresh failed - clear tokens and redirect to login
                    tokenManager.clearTokens();
                    tokenManager.setRefreshing(false);

                    // Dispatch auth failure event for app to handle
                    window.dispatchEvent(new CustomEvent('auth:sessionExpired'));

                    return Promise.reject(refreshError);
                }
            }

            return Promise.reject(error);
        }
    );

    return client;
};

// Singleton instance
export const apiClient = createSecureClient();

// Re-export for convenience
export { tokenManager } from './tokenManager';
