import { Injectable, inject } from '@angular/core';
import { Role } from '../constants/role.code';
import { firstValueFrom } from 'rxjs';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { Router } from '@angular/router';
import { StorageService } from './storage.service';

@Injectable({
    providedIn: 'root',
})
export class ProfileService {
    private _router = inject(Router);
    private _storageService = inject(StorageService);

    private baseUrl: string = environment.apiUrl;
    selfProfileData: any;

    constructor(private http: HttpClient) {}

    async ngOnInit() {
        this.selfProfileData = await this.getSelfProfileData();
    }

    async getSelfProfileData() {
        try {
            const response: any = await firstValueFrom(
                this.http.get(`${this.baseUrl}/user/userDetails`, {
                    observe: 'response',
                }),
            );
            console.log('ProfileService | getSelfProfileData - response -> ', response.body);

            this.selfProfileData = response.body;
            return this.selfProfileData;
        } catch (error: any) {
            console.error('Error fetching profile data', error);
            this.logout();
            throw error;
        }
    }

    async getSelfProfileDataWithoutLoading() {
        if (!this.selfProfileData) await this.getSelfProfileData();
        return this.selfProfileData;
    }

    async getRole() {
        if (!this.selfProfileData) await this.getSelfProfileData();
        return this.selfProfileData.role;
    }

    async getUserID() {
        if (!this.selfProfileData) await this.getSelfProfileData();
        return this.selfProfileData.id;
    }

    async updateProfile(data: any) {
        try {
            const response: any = await firstValueFrom(this.http.post(`${this.baseUrl}/user/update/`, { data: data }));
            return response;
        } catch (error: any) {
            console.error('Error updating profile data', error);
            throw error;
        }
    }

    logout() {
        this.selfProfileData = null;
        this._storageService.removeItem('token');
        this._storageService.removeItem('refresh');
        this._router.navigateByUrl('/landing');
    }
}
