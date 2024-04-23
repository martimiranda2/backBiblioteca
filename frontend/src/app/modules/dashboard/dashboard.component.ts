import { Component, inject } from '@angular/core';

import { ButtonModule } from 'primeng/button';
import { AvatarModule } from 'primeng/avatar';
import { AvatarGroupModule } from 'primeng/avatargroup';
import { InputTextModule } from 'primeng/inputtext';

import { ProfileService } from '../../services/profile.service';
import { DialogService } from '../../services/dialog.service';
import { AuthService } from '../../core/auth/auth.service';
import { PasswordModule } from 'primeng/password';
import { FormsModule } from '@angular/forms';

@Component({
    selector: 'app-dashboard',
    standalone: true,
    imports: [ButtonModule, AvatarModule, AvatarGroupModule, InputTextModule, PasswordModule, FormsModule],
    templateUrl: './dashboard.component.html',
    styleUrl: './dashboard.component.css',
})
export class DashboardComponent {
    _profileService = inject(ProfileService);
    _dialogService = inject(DialogService);
    _authService = inject(AuthService);

    profileData: any;
    originalProfileData: any;
    role: any;
    roleName: string = '';
    initials: string = '';

    isEditingName = false;
    isEditingEmail = false;
    isEditingPassword = false;

    newName!: string;
    newSurname!: string;
    newSurname2!: string;
    newEmail!: string;
    lastPassword!: string;
    password!: string;
    repeatPassword!: string;

    async ngOnInit() {
        this.profileData = await this._profileService.getSelfProfileDataWithoutLoading();
        this.originalProfileData = JSON.parse(JSON.stringify(this.profileData));

        this.role = await this._profileService.getRole();
        this.roleName = this.getRoleName();
        this.initials = this.getInitials();
    }

    getRoleName() {
        if (this.role === 1) return 'Administrador';
        if (this.role === 2) return 'Professor';
        if (this.role === 3) return 'Alumne';
        if (this.role === 4) return 'Bibliotecària';
        return '';
    }

    getInitials() {
        if (this.profileData && this.profileData.name && this.profileData.surname) {
            let initials = this.profileData.name[0].toUpperCase() + this.profileData.surname[0].toUpperCase();
            return initials;
        }
        return '';
    }

    cancelChanges() {
        this.profileData = JSON.parse(JSON.stringify(this.originalProfileData));
        this.isEditingName = false;
        this.isEditingEmail = false;
        this.isEditingPassword = false;
    }

    async saveChanges() {
        let updateData: any = {};

        if (this.newName) {
            updateData['first_name'] = this.newName;
        }
        if (this.newSurname) {
            updateData['last_name'] = this.newSurname;
        }
        if (this.newSurname2) {
            updateData['second_last_name'] = this.newSurname2;
        }
        if (this.newEmail) {
            updateData['email'] = this.newEmail;
        }
        if (this.lastPassword || this.password || this.repeatPassword) {
            await this.updatePassword();
        }

        try {
            const response = await this._profileService.updateProfile(updateData);
            console.log('DashboardComponent | saveChanges - response -> ', response);

            // Actualizar la interfaz de usuario con los nuevos valores
            if (this.newName) {
                this.profileData.first_name = this.newName;
            }
            if (this.newSurname) {
                this.profileData.last_name = this.newSurname;
            }
            if (this.newSurname2) {
                this.profileData.second_last_name = this.newSurname2;
            }
            if (this.newEmail) {
                this.profileData.email = this.newEmail;
            }

            this._dialogService.showDialog('INFORMACIÓ', 'Perfil actualitzat correctament');
        } catch (error) {
            console.error('Error updating profile:', error);
            this._dialogService.showDialog('ERROR', 'Error al actualizar el perfil');
        }
    }

    async updatePassword() {
        try {
            const response = await this._authService.isValidPassword(this.profileData.username, this.lastPassword);
            if (response) {
                if (this.password.length < 8 || this.repeatPassword.length < 8) {
                    this._dialogService.showDialog('ERROR', 'La contrasenya ha de tenir com a mínim 8 caràcters');
                } else if (this.password === this.repeatPassword) {
                    await this._authService.saveNewPassword(this.profileData.username, this.password);
                    this._dialogService.showDialog('INFORMACIÓ', "S'ha actualitzat la contrasenya correctament");
                } else {
                    this._dialogService.showDialog('ERROR', 'Les contrasenyes no coincideixen');
                }
            } else {
                throw new Error('Contrasenya incorrecta');
            }
        } catch (error: any) {
            this._dialogService.showDialog('ERROR', error.message);
        }
    }
}
