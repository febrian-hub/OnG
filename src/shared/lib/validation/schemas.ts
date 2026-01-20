/**
 * Common Zod Schemas
 * 
 * Reusable validation schemas for common data types.
 */

import { z } from 'zod';

// ============================================
// Primitive Schemas
// ============================================

export const emailSchema = z
    .string()
    .min(1, 'Email is required')
    .email('Invalid email address');

export const passwordSchema = z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character');

export const passwordConfirmSchema = z
    .string()
    .min(1, 'Please confirm your password');

export const uuidSchema = z.string().uuid('Invalid ID format');

export const dateStringSchema = z.string().datetime('Invalid date format');

// ============================================
// API Response Schemas
// ============================================

export const apiErrorSchema = z.object({
    message: z.string(),
    code: z.string().optional(),
    errors: z.record(z.string()).optional(),
});

export const paginationSchema = z.object({
    page: z.number().int().positive(),
    limit: z.number().int().positive(),
    total: z.number().int().nonnegative(),
    totalPages: z.number().int().nonnegative(),
});

export const paginatedResponseSchema = <T extends z.ZodTypeAny>(itemSchema: T) =>
    z.object({
        data: z.array(itemSchema),
        pagination: paginationSchema,
    });

// ============================================
// Auth Schemas
// ============================================

export const loginRequestSchema = z.object({
    email: emailSchema,
    password: z.string().min(1, 'Password is required'),
});

export const registerRequestSchema = z
    .object({
        email: emailSchema,
        password: passwordSchema,
        confirmPassword: passwordConfirmSchema,
        name: z.string().min(2, 'Name must be at least 2 characters'),
    })
    .refine((data) => data.password === data.confirmPassword, {
        message: 'Passwords do not match',
        path: ['confirmPassword'],
    });

export const authResponseSchema = z.object({
    accessToken: z.string(),
    refreshToken: z.string().optional(),
    user: z.object({
        id: uuidSchema,
        email: emailSchema,
        name: z.string(),
    }),
});

// Type exports
export type LoginRequest = z.infer<typeof loginRequestSchema>;
export type RegisterRequest = z.infer<typeof registerRequestSchema>;
export type AuthResponse = z.infer<typeof authResponseSchema>;
export type ApiError = z.infer<typeof apiErrorSchema>;
export type Pagination = z.infer<typeof paginationSchema>;
