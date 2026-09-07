import { Injectable, signal, computed } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, tap } from 'rxjs';

import { environment } from '../../../environments/environment';
import { TokenPair, User, Role } from '../models';

const ACCESS_KEY = 'socmind_access';
const REFRESH_KEY = 'socmind_refresh';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private base = environment.apiBase;

  // Signals hold reactive auth state for the whole app.
  readonly user = signal<User | null>(null);
  readonly isAuthenticated = computed(() => this.user() !== null);

  constructor(private http: HttpClient) {}

  login(email: string, password: string): Observable<TokenPair> {
    // Backend expects OAuth2 form fields: username + password.
    const body = new URLSearchParams();
    body.set('username', email);
    body.set('password', password);

    return this.http
      .post<TokenPair>(`${this.base}/api/auth/login`, body.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      })
      .pipe(
        tap((tokens) => {
          localStorage.setItem(ACCESS_KEY, tokens.access_token);
          localStorage.setItem(REFRESH_KEY, tokens.refresh_token);
        })
      );
  }

  loadCurrentUser(): Observable<User> {
    return this.http
      .get<User>(`${this.base}/api/auth/me`)
      .pipe(tap((u) => this.user.set(u)));
  }

  logout(): void {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
    this.user.set(null);
  }

  get accessToken(): string | null {
    return localStorage.getItem(ACCESS_KEY);
  }

  hasRole(...roles: Role[]): boolean {
    const u = this.user();
    return !!u && roles.includes(u.role);
  }
}
