import { HttpEvent, HttpHandler, HttpInterceptor, HttpRequest } from '@angular/common/http';
import { Injectable, Injector, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { JwtHelperService } from '@auth0/angular-jwt';
import { AuthService } from '../core/auth/auth.service';
import { environment } from '../../environments/environment';
import { Router } from '@angular/router';

@Injectable()
export class JwtInterceptor implements HttpInterceptor {
    injector = inject(Injector);
    jwtHelper = inject(JwtHelperService);
    _router = inject(Router);

    baseUrl: string = environment.apiUrl;
    refreshInProgress = false;
    secondsUntillRefresh = 3600; // 1h

    intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        const authService = this.injector.get(AuthService);

        // Skip jwt injection on foreign calls and auth calls
        if (!req.url.startsWith(environment.apiUrl)) return next.handle(req);

        const token: string = authService.getToken();

        try {
            // Skip jwt injection when the client is unidentified
            if (!token) return next.handle(req);
            if (token) {
                // Skip refresh check on refreshToken call
                if (req.url.toLowerCase() != `${this.baseUrl}/auth/refresh`) {
                    const now = Math.floor(Date.now() / 1000); // timestamp in seconds
                    const iat = this.jwtHelper.decodeToken(token).iat; // timestamp in seconds that the token was issued at

                    if (!this.refreshInProgress && iat < now - this.secondsUntillRefresh) {
                        this.refreshInProgress = true;
                        authService
                            .refreshToken()
                            .then(() => (this.refreshInProgress = false))
                            .catch(() => (this.refreshInProgress = false));
                    }
                }
            }
        } catch (error) {
            this._router.navigateByUrl('/login');
        }

        const newReq = req.clone({
            headers: req.headers.set('Authorization', `Bearer ${token}`),
        });
        return next.handle(newReq);
    }
}
