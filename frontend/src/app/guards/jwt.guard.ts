import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { CanActivateFn } from '@angular/router';
import { AuthService } from '../core/auth/auth.service';

export const JwtGuard: CanActivateFn = () => {
    const authService = inject(AuthService);
    const router = inject(Router);

    const token = authService.getToken();
    if (token) return true;

    return router.navigateByUrl('/login');
};
