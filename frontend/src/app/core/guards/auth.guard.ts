import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';

import { AuthService } from '../services/auth.service';
import { Role } from '../models';

/** Blocks routes unless a token is present (FR-1..4). */
export const authGuard: CanActivateFn = () => {
  const auth = inject(AuthService);
  const router = inject(Router);
  if (auth.accessToken) return true;
  router.navigate(['/login']);
  return false;
};

/** Factory for role-gated routes (FR-3 RBAC). */
export const roleGuard = (...roles: Role[]): CanActivateFn => {
  return () => {
    const auth = inject(AuthService);
    const router = inject(Router);
    if (auth.hasRole(...roles)) return true;
    router.navigate(['/dashboard']);
    return false;
  };
};
