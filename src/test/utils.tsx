/**
 * Test Utilities
 * 
 * Reusable test helpers and wrappers.
 */

import { render, type RenderOptions } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactElement, ReactNode } from 'react';

/**
 * Create a fresh QueryClient for tests
 */
function createTestQueryClient() {
    return new QueryClient({
        defaultOptions: {
            queries: {
                retry: false,
                gcTime: 0,
            },
        },
    });
}

/**
 * Test wrapper with providers
 */
interface TestWrapperProps {
    children: ReactNode;
}

function TestWrapper({ children }: TestWrapperProps) {
    const queryClient = createTestQueryClient();
    return (
        <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    );
}

/**
 * Custom render with providers
 */
function customRender(
    ui: ReactElement,
    options?: Omit<RenderOptions, 'wrapper'>
) {
    return render(ui, { wrapper: TestWrapper, ...options });
}

// Re-export everything
export * from '@testing-library/react';
export { customRender as render };
