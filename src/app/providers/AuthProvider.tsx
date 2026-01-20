/**
 * Auth Context & Provider
 * 
 * Provides authentication state and methods throughout the app.
 * Integrates with the secure token manager.
 */

import {
    createContext,
    useContext,
    useCallback,
    useEffect,
    useState,
    useMemo,
    type ReactNode,
} from 'react';
import { apiClient, tokenManager } from '@shared/api';
import { API_CONFIG } from '@shared/config';
import { validateOrThrow } from '@shared/lib/validation';
import { authResponseSchema } from '@shared/lib/validation/schemas';
import type { User, AuthState } from '@shared/types';

// ============================================
// Types
// ============================================

interface AuthContextValue extends AuthState {
    login: (email: string, password: string) => Promise<void>;
    logout: () => Promise<void>;
    register: (email: string, password: string, name: string) => Promise<void>;
}

interface AuthProviderProps {
    children: ReactNode;
}

// ============================================
// Context
// ============================================

const AuthContext = createContext<AuthContextValue | null>(null);

// ============================================
// Provider Component
// ============================================

export function AuthProvider({ children }: AuthProviderProps) {
    const [state, setState] = useState<AuthState>({
        user: null,
        isAuthenticated: false,
        isLoading: true,
    });

    /**
     * Fetch current user on mount if token exists
     */
    useEffect(() => {
        const initAuth = async () => {
            if (!tokenManager.hasAccessToken()) {
                setState((prev) => ({ ...prev, isLoading: false }));
                return;
            }

            try {
                const response = await apiClient.get<User>(API_CONFIG.endpoints.me);
                setState({
                    user: response.data,
                    isAuthenticated: true,
                    isLoading: false,
                });
            } catch {
                tokenManager.clearTokens();
                setState({
                    user: null,
                    isAuthenticated: false,
                    isLoading: false,
                });
            }
        };

        initAuth();
    }, []);

    /**
     * Handle session expiration
     */
    useEffect(() => {
        const handleSessionExpired = () => {
            setState({
                user: null,
                isAuthenticated: false,
                isLoading: false,
            });
        };

        window.addEventListener('auth:sessionExpired', handleSessionExpired);
        return () =>
            window.removeEventListener('auth:sessionExpired', handleSessionExpired);
    }, []);

    /**
     * Login with email and password
     */
    const login = useCallback(async (email: string, password: string) => {
        const response = await apiClient.post(API_CONFIG.endpoints.login, {
            email,
            password,
        });

        const validated = validateOrThrow(
            authResponseSchema,
            response.data,
            'Login response'
        );

        tokenManager.setTokens(validated.accessToken, validated.refreshToken);
        setState({
            user: validated.user,
            isAuthenticated: true,
            isLoading: false,
        });
    }, []);

    /**
     * Register new user
     */
    const register = useCallback(
        async (email: string, password: string, name: string) => {
            const response = await apiClient.post(API_CONFIG.endpoints.register, {
                email,
                password,
                name,
            });

            const validated = validateOrThrow(
                authResponseSchema,
                response.data,
                'Register response'
            );

            tokenManager.setTokens(validated.accessToken, validated.refreshToken);
            setState({
                user: validated.user,
                isAuthenticated: true,
                isLoading: false,
            });
        },
        []
    );

    /**
     * Logout user
     */
    const logout = useCallback(async () => {
        try {
            await apiClient.post(API_CONFIG.endpoints.logout);
        } finally {
            tokenManager.clearTokens();
            setState({
                user: null,
                isAuthenticated: false,
                isLoading: false,
            });
        }
    }, []);

    const value = useMemo<AuthContextValue>(
        () => ({
            ...state,
            login,
            logout,
            register,
        }),
        [state, login, logout, register]
    );

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// ============================================
// Hook
// ============================================

export function useAuth(): AuthContextValue {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
}
