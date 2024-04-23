import { Component, inject } from '@angular/core';
import { RouterModule } from '@angular/router';

import { DialogModule } from 'primeng/dialog';
import { ButtonModule } from 'primeng/button';

import { DialogService } from '../../services/dialog.service';

@Component({
    selector: 'app-layout',
    standalone: true,
    templateUrl: './layout.component.html',
    styleUrl: './layout.component.css',
    imports: [RouterModule, DialogModule, ButtonModule],
})
export class LayoutComponent {
    _dialogService = inject(DialogService);

    isVisible: boolean = false;
    header: string = 'INTORMACIÓ';
    message: string = '';

    async ngOnInit() {
        this._dialogService.showDialog$.subscribe(({ isVisible, header, message }) => {
            this.isVisible = isVisible;
            this.header = header;
            this.message = message;
        });
    }
}
