/**
 * App Entry Point
 * 
 * Composes all providers and renders the application.
 */

import { StrictMode } from 'react';
import { QueryProvider, AuthProvider } from './providers';

interface AppProps {
    children: React.ReactNode;
}

export function App({ children }: AppProps) {
    return (
        <StrictMode>
            <QueryProvider>
                <AuthProvider>{children}</AuthProvider>
            </QueryProvider>
        </StrictMode>
    );
}

export default App;
