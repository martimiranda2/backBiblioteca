import { Injectable, Injector, inject } from '@angular/core';
import { HttpEvent, HttpInterceptor, HttpHandler, HttpRequest } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Router } from '@angular/router';
import { LogService } from '../services/log.service';
import { environment } from '../../environments/environment';
import { AuthService } from '../core/auth/auth.service';

@Injectable()
export class LogInterceptor implements HttpInterceptor {
    injector = inject(Injector);
    _router = inject(Router);
    _logService = inject(LogService);

    baseUrl: string = environment.apiUrl;

    intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        const authService = this.injector.get(AuthService);

        const token: string = authService.getToken();

        try {
            // Skip log when the client is unidentified
            if (!token) return next.handle(req);
            if (req.url.toLowerCase() != `${this.baseUrl}/logs/save`) {
                this._logService.sendLogs();
            }
        } catch (error) {
            this._router.navigateByUrl('/login');
        }
        return next.handle(req);
    }
}
