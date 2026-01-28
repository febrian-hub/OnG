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

import { BrowserRouter } from 'react-router-dom';

export function App({ children }: AppProps) {
    return (
        <StrictMode>
            <QueryProvider>
                <AuthProvider>
                    <BrowserRouter>
                        {children}
                    </BrowserRouter>
                </AuthProvider>
            </QueryProvider>
        </StrictMode>
    );
}

export default App;
