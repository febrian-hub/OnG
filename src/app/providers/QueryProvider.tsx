/**
 * React Query Provider
 * 
 * Configures TanStack Query with secure defaults.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';

// Configure QueryClient with secure defaults
const queryClient = new QueryClient({
    defaultOptions: {
        queries: {
            // Don't retry on 401/403 - auth errors should be handled by interceptors
            retry: (failureCount, error) => {
                if (
                    error &&
                    typeof error === 'object' &&
                    'response' in error &&
                    error.response &&
                    typeof error.response === 'object' &&
                    'status' in error.response
                ) {
                    const status = (error.response as { status: number }).status;
                    if (status === 401 || status === 403) {
                        return false;
                    }
                }
                return failureCount < 3;
            },
            // Refetch on window focus for fresh data
            refetchOnWindowFocus: true,
            // Don't keep stale data too long
            staleTime: 5 * 60 * 1000, // 5 minutes
            gcTime: 10 * 60 * 1000, // 10 minutes
        },
        mutations: {
            retry: false, // Don't retry mutations
        },
    },
});

interface QueryProviderProps {
    children: ReactNode;
}

export function QueryProvider({ children }: QueryProviderProps) {
    return (
        <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    );
}

export { queryClient };
