/**
 * Global Type Definitions
 */

// ============================================
// Utility Types
// ============================================

/**
 * Make all properties of T optional except for keys in K
 */
export type PartialExcept<T, K extends keyof T> = Partial<T> & Pick<T, K>;

/**
 * Make specific keys required
 */
export type RequiredKeys<T, K extends keyof T> = T & Required<Pick<T, K>>;

/**
 * Extract the resolved type from a Promise
 */
export type Awaited<T> = T extends Promise<infer U> ? U : T;

/**
 * Make all properties deeply readonly
 */
export type DeepReadonly<T> = {
    readonly [P in keyof T]: T[P] extends object ? DeepReadonly<T[P]> : T[P];
};

// ============================================
// API Types
// ============================================

export interface ApiResponse<T = unknown> {
    data: T;
    message?: string;
    status: number;
}

export interface ApiErrorResponse {
    message: string;
    code?: string;
    errors?: Record<string, string>;
    status: number;
}

export interface PaginationParams {
    page?: number;
    limit?: number;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
}

export interface PaginatedResponse<T> {
    data: T[];
    pagination: {
        page: number;
        limit: number;
        total: number;
        totalPages: number;
    };
}

// ============================================
// Component Types
// ============================================

export interface BaseComponentProps {
    className?: string;
    children?: React.ReactNode;
}

// ============================================
// Auth Types
// ============================================

export interface User {
    id: string;
    email: string;
    name: string;
    avatar?: string;
    createdAt?: string;
    updatedAt?: string;
}

export interface AuthState {
    user: User | null;
    isAuthenticated: boolean;
    isLoading: boolean;
}
