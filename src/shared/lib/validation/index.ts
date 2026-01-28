/**
 * Zod Validation Utilities
 * 
 * Type-safe validation helpers for API responses and forms.
 */

import { type ZodSchema, type ZodError } from 'zod';

/**
 * Result type for validation operations
 */
export type ValidationResult<T> =
    | { success: true; data: T }
    | { success: false; error: ZodError };

/**
 * Safely validate data against a Zod schema
 */
export function validate<T>(
    schema: ZodSchema<T>,
    data: unknown
): ValidationResult<T> {
    const result = schema.safeParse(data);
    if (result.success) {
        return { success: true, data: result.data };
    }
    return { success: false, error: result.error };
}

/**
 * Validate API response and throw on failure
 * Use this when you want the app to fail fast on invalid responses
 */
export function validateOrThrow<T>(
    schema: ZodSchema<T>,
    data: unknown,
    context?: string
): T {
    const result = schema.safeParse(data);
    if (!result.success) {
        console.error(
            `[Validation Error]${context ? ` ${context}` : ''}:`,
            result.error.format()
        );
        throw new Error(
            `Invalid data structure${context ? ` for ${context}` : ''}`
        );
    }
    return result.data;
}

/**
 * Format Zod errors for display
 */
export function formatZodErrors(error: ZodError): Record<string, string> {
    const formattedErrors: Record<string, string> = {};

    (error as any).errors.forEach((err: any) => {
        const path = err.path.join('.');
        if (path && !formattedErrors[path]) {
            formattedErrors[path] = err.message;
        }
    });

    return formattedErrors;
}

/**
 * Create a validated fetch wrapper
 */
export function createValidatedFetch<T>(schema: ZodSchema<T>) {
    return async (fetchFn: () => Promise<unknown>): Promise<T> => {
        const data = await fetchFn();
        return validateOrThrow(schema, data);
    };
}

// Re-export Zod for convenience
export { z } from 'zod';
export type { ZodSchema, ZodError } from 'zod';
