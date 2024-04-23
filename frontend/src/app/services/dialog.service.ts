import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

@Injectable({
    providedIn: 'root',
})
export class DialogService {
    private _showDialog = new BehaviorSubject<{ isVisible: boolean; header: string; message: string }>({ isVisible: false, header: '', message: '' });
    showDialog$ = this._showDialog.asObservable();

    showDialog(header: string = 'INFORMACIÓ', message: string) {
        this._showDialog.next({ isVisible: true, header, message });
    }

    hideDialog() {
        this._showDialog.next({ isVisible: false, header: '', message: '' });
    }
}
