import { HttpInterceptorFn } from '@angular/common/http';

const ACCESS_KEY = 'socmind_access';

/** Attaches the bearer token to every API request (FR-4 session security). */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const token = localStorage.getItem(ACCESS_KEY);
  if (token && req.url.includes('/api/')) {
    req = req.clone({
      setHeaders: { Authorization: `Bearer ${token}` },
    });
  }
  return next(req);
};
