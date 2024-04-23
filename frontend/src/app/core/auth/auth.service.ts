import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { environment } from '../../../environments/environment';
import { StorageService } from '../../services/storage.service';
import { Router } from '@angular/router';

@Injectable({
    providedIn: 'root',
})
export class AuthService {
    _http = inject(HttpClient);
    _storage = inject(StorageService);
    _router = inject(Router);

    private baseUrl: string = environment.apiUrl;

    async login(username: string, password: string) {
        const body = { username: username, password: password };

        try {
            let response: any = await firstValueFrom(
                this._http.post(`${this.baseUrl}/auth/login/`, body, {
                    observe: 'response',
                    withCredentials: true,
                    headers: {
                        'Content-Type': 'application/json',
                    },
                }),
            );

            this._storage.setItem('token', response.body.token.access);
            this._storage.setItem('refresh', response.body.token.refresh);
            return response;
        } catch (error: any) {
            if (error.status === 401) {
                throw new Error('Contrasenya incorrecta');
            } else {
                console.error('Error during password validation', error);
                throw error;
            }
        }
    }

    async validateToken(): Promise<boolean> {
        try {
            const response = await firstValueFrom(
                this._http.get(`${this.baseUrl}/auth/verify`, {
                    observe: 'response',
                }),
            );
            return response ? true : false;
        } catch (error: any) {
            console.error('Error during token validation', error);
            return false;
        }
    }

    getToken() {
        return this._storage.getItem('token') || '';
    }

    async refreshToken() {
        const refreshToken = this._storage.getItem('refresh');
        if (!refreshToken) {
            this._router.navigate(['/login']);
            return;
        }
        try {
            let response: any = await firstValueFrom(this._http.post(`${this.baseUrl}/auth/refresh/`, { refreshToken: refreshToken }));
            if (!response.token) {
                throw new Error('Token is undefined or null');
            }
            this._storage.setItem('token', response.token);
        } catch (error: any) {
            console.error('Error during token refresh', error);
            throw error;
        }
    }

    async isValidPassword(email: string, password: string) {
        try {
            let response: any = await firstValueFrom(this._http.post(`${this.baseUrl}/auth/verify-password/`, { email: email, password: password }));
            return response.isValid;
        } catch (error: any) {
            if (error.status === 401) {
                throw new Error('Contrasenya incorrecta');
            } else {
                console.error('Error during password validation', error);
                throw error;
            }
        }
    }

    async saveNewPassword(email: string, password: string) {
        try {
            let response: any = await firstValueFrom(this._http.post(`${this.baseUrl}/auth/save-password/`, { email: email, password: password }));
            return response;
        } catch (error: any) {
            console.error('Error during password saving', error);
            throw error;
        }
    }
}
