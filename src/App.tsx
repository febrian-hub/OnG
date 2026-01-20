/**
 * Root Application Component
 * 
 * This is the main entry point wrapped by providers in main.tsx
 */

function App() {
  return (
    <div className="min-h-screen bg-slate-900 text-white">
      <div className="container mx-auto px-4 py-16">
        <header className="text-center mb-12">
          <h1 className="text-4xl font-bold mb-4 bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">
            🛡️ Secure React Foundation
          </h1>
          <p className="text-slate-400 text-lg">
            Security-First Architecture with Feature-Sliced Design
          </p>
        </header>

        <main className="max-w-2xl mx-auto">
          <div className="bg-slate-800/50 backdrop-blur-sm rounded-xl p-8 border border-slate-700">
            <h2 className="text-xl font-semibold mb-4 text-slate-200">
              ✅ Project Setup Complete
            </h2>

            <ul className="space-y-3 text-slate-300">
              <li className="flex items-center gap-2">
                <span className="text-green-400">●</span>
                TypeScript Strict Mode
              </li>
              <li className="flex items-center gap-2">
                <span className="text-green-400">●</span>
                Feature-Sliced Design Architecture
              </li>
              <li className="flex items-center gap-2">
                <span className="text-green-400">●</span>
                Secure API Client (CSRF + Token Refresh)
              </li>
              <li className="flex items-center gap-2">
                <span className="text-green-400">●</span>
                Zod Validation
              </li>
              <li className="flex items-center gap-2">
                <span className="text-green-400">●</span>
                TanStack Query
              </li>
              <li className="flex items-center gap-2">
                <span className="text-green-400">●</span>
                Vitest Testing Framework
              </li>
            </ul>

            <div className="mt-6 pt-6 border-t border-slate-700">
              <p className="text-sm text-slate-500">
                See <code className="text-blue-400">docs/ADDING_FEATURES.md</code> to start building
              </p>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

export default App;
