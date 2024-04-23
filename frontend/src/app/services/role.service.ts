import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { ProfileService } from './profile.service';
import { environment } from '../../environments/environment';
import { Role } from '../constants/role.code';
// import { IRole, createRole } from '../interfaces/irole';

@Injectable({
    providedIn: 'root',
})
export class RoleService {
    _profile = inject(ProfileService);

    private baseUrl: string = environment.apiUrl;

    constructor(private http: HttpClient) {}

    async getRoleList() {
        let response: any = await firstValueFrom(this.http.get(`${this.baseUrl}/role`, { observe: 'response' }));
        response = response.body;
        return response;
    }

    async getRoleById(roleId: string) {
        let response: any = await firstValueFrom(
            this.http.get(`${this.baseUrl}/role/${roleId}`, {
                observe: 'response',
            }),
        );
        response = response.body;
        return response[0];
    }

    async deleteRoleById(roleId: string) {
        let response: any = await firstValueFrom(
            this.http.delete(`${this.baseUrl}/role/${roleId}`, {
                observe: 'response',
            }),
        );
        response = response.body;
        return response;
    }

    async updateRoleById(roleId: string, role: any) {
        let response: any = await firstValueFrom(
            this.http.patch(`${this.baseUrl}/role/${roleId}`, role, {
                observe: 'response',
            }),
        );
        response = response.body;
        return response;
    }

    async createRole(role: any) {
        let response: any = await firstValueFrom(
            this.http.post(`${this.baseUrl}/role/create`, role, {
                observe: 'response',
            }),
        );
        response = response.body;
        return response;
    }
}
