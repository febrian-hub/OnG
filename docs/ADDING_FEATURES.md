# Adding a New Feature

This document describes how to add a new feature following the established FSD architecture and security standards.

## 1. Create Feature Structure

```bash
mkdir -p src/features/<feature-name>/{api,model,ui}
touch src/features/<feature-name>/index.ts
```

Example for an "auth" feature:

```
src/features/auth/
├── api/
│   ├── authApi.ts          # API calls using secure client
│   └── index.ts
├── model/
│   ├── authSchemas.ts      # Zod schemas for validation
│   ├── useAuth.ts          # React Query hooks
│   └── index.ts
├── ui/
│   ├── LoginForm.tsx       # UI components
│   └── index.ts
└── index.ts                # Public API
```

## 2. API Layer Rules

```typescript
// ✅ CORRECT: Use the secure API client
import { apiClient } from '@shared/api';
import { validateOrThrow } from '@shared/lib/validation';
import { mySchema } from './model/schemas';

export async function fetchData() {
  const response = await apiClient.get('/endpoint');
  return validateOrThrow(mySchema, response.data);
}
```

```typescript
// ❌ WRONG: Never use raw fetch/axios
import axios from 'axios'; // NEVER import axios directly
```

## 3. Validation Rules

All API responses MUST be validated with Zod:

```typescript
// In model/schemas.ts
import { z } from 'zod';

export const userSchema = z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  name: z.string(),
});

export type User = z.infer<typeof userSchema>;
```

## 4. Testing Requirements

Create tests in the feature directory:

```
src/features/<feature-name>/
├── __tests__/
│   ├── api.test.ts
│   └── ui.test.tsx
```

### Required Test Coverage

1. **Happy path** - Feature works as expected
2. **401 Unauthorized** - Session expired handling
3. **403 Forbidden** - Permission denied handling
4. **429 Rate Limited** - Rate limit handling
5. **Validation failures** - Invalid data handling

Example:

```typescript
import { describe, it, expect, vi } from 'vitest';
import { apiClient } from '@shared/api';

vi.mock('@shared/api');

describe('myFeatureApi', () => {
  it('handles 401 unauthorized', async () => {
    vi.mocked(apiClient.get).mockRejectedValue({
      response: { status: 401 }
    });
    
    // Test behavior
  });
});
```

## 5. Export Public API

Only export what external modules need:

```typescript
// src/features/auth/index.ts
export { LoginForm } from './ui';
export { useLogin, useLogout } from './model';
export type { LoginFormData } from './model';
```

## 6. Update Feature Index

Add export to `src/features/index.ts`:

```typescript
export * from './auth';
export * from './your-new-feature';
```

## 7. Run Verification

```bash
# Type check
npm run typecheck

# Lint
npm run lint

# Test
npm run test:run

# Generate test report
npm run test:report
```

## Security Checklist

- [ ] Uses `apiClient` from `@shared/api`
- [ ] All API responses validated with Zod
- [ ] No sensitive data in component state that could leak
- [ ] Error handling for 401/403/429
- [ ] Tests cover security scenarios
