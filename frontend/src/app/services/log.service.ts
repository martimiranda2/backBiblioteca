import { Injectable, inject } from '@angular/core';
import { environment } from '../../environments/environment';
import { HttpClient } from '@angular/common/http';
import { ProfileService } from './profile.service';
import { firstValueFrom } from 'rxjs';

@Injectable({
    providedIn: 'root',
})
export class LogService {
    private _profileService = inject(ProfileService);

    private baseUrl: string = environment.apiUrl + '/log';
    private logsKey = 'logs';

    constructor(private http: HttpClient) {}

    logInfo(message: string, object: any) {
        let log = { level: 'INFO', message, object };
        this.saveLogInStorage(log);
    }

    logWarning(message: string, object: any) {
        let log = { level: 'WARNING', message, object };
        this.saveLogInStorage(log);
    }

    logError(message: string, object: any) {
        let log = { level: 'ERROR', message, object };
        this.saveLogInStorage(log);
    }

    logFatal(message: string, object: any) {
        let log = { level: 'FATAL', message, object };
        this.saveLogInStorage(log);
    }

    // Método para guardar un nuevo log en el localStorage
    async saveLogInStorage(log: any) {
        const userID = await this._profileService.getUserID();
        const timestamp = new Date().toISOString();
        log = { ...log, userID, timestamp };
        let logs: any[] = JSON.parse(localStorage.getItem(this.logsKey) || '[]');
        logs.push(log);
        localStorage.setItem(this.logsKey, JSON.stringify(logs));
    }

    // Método para obtener todos los logs guardados en el localStorage
    getLogs(): any[] {
        return JSON.parse(localStorage.getItem(this.logsKey) || '[]');
    }

    // Método para limpiar todos los logs del localStorage
    clearLogs() {
        localStorage.removeItem(this.logsKey);
    }

    async sendLogs() {
        const logs = this.getLogs();
        if (logs.length == 0) return;

        try {
            let response: any = await firstValueFrom(
                this.http.post(`${this.baseUrl}/logs/save`, logs, {
                    observe: 'response',
                }),
            );
            if (response.status !== 200) {
                throw new Error('Error sending logs');
            }
            this.logInfo('Logs sent successfully', logs);
            response = response.body;
            this.clearLogs();
            return response;
        } catch (error) {
            console.error('Error sending logs', error);
            this.logError('LogService | sendLogs() ---> Error sending logs', logs);
        }
    }
}
