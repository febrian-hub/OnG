/**
 * Token Manager Tests
 * 
 * Verifies secure token storage behavior.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { tokenManager } from '@shared/api/tokenManager';

describe('tokenManager', () => {
    beforeEach(() => {
        tokenManager.clearTokens();
    });

    describe('token storage', () => {
        it('stores access token in memory', () => {
            tokenManager.setTokens('test-access-token');
            expect(tokenManager.getAccessToken()).toBe('test-access-token');
        });

        it('stores both access and refresh tokens', () => {
            tokenManager.setTokens('access', 'refresh');
            expect(tokenManager.getAccessToken()).toBe('access');
            expect(tokenManager.getRefreshToken()).toBe('refresh');
        });

        it('clears all tokens', () => {
            tokenManager.setTokens('access', 'refresh');
            tokenManager.clearTokens();
            expect(tokenManager.getAccessToken()).toBeNull();
            expect(tokenManager.getRefreshToken()).toBeNull();
        });

        it('reports hasAccessToken correctly', () => {
            expect(tokenManager.hasAccessToken()).toBe(false);
            tokenManager.setTokens('token');
            expect(tokenManager.hasAccessToken()).toBe(true);
        });
    });

    describe('refresh state', () => {
        it('tracks refresh state', () => {
            expect(tokenManager.isRefreshing()).toBe(false);
            tokenManager.setRefreshing(true);
            expect(tokenManager.isRefreshing()).toBe(true);
            tokenManager.setRefreshing(false);
            expect(tokenManager.isRefreshing()).toBe(false);
        });
    });

    describe('security', () => {
        it('does not expose tokens on window object', () => {
            tokenManager.setTokens('secret-token');

            // Verify token is not accessible via common attack vectors
            expect((window as Record<string, unknown>)['accessToken']).toBeUndefined();
            expect((window as Record<string, unknown>)['tokenStore']).toBeUndefined();
        });
    });
});
