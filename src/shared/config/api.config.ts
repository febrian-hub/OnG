/**
 * API Configuration
 * 
 * Centralized configuration for API endpoints and settings.
 * Environment-aware with sensible defaults.
 */

export const API_CONFIG = {
    baseURL: import.meta.env['VITE_API_BASE_URL'] || '/api/v1',
    timeout: Number(import.meta.env['VITE_API_TIMEOUT']) || 30000,

    endpoints: {
        // Auth endpoints
        login: '/auth/login',
        logout: '/auth/logout',
        refreshToken: '/auth/refresh-token',
        register: '/auth/register',
        forgotPassword: '/auth/forgot-password',
        resetPassword: '/auth/reset-password',

        // User endpoints
        me: '/users/me',
        users: '/users',
    },
} as const;

// Type for endpoint keys
export type ApiEndpoint = keyof typeof API_CONFIG.endpoints;
