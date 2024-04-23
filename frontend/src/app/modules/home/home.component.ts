import { Component, OnInit } from '@angular/core';
import { ButtonModule } from 'primeng/button';
import { FormsModule }   from '@angular/forms';
import { AutoCompleteModule } from 'primeng/autocomplete';
import { ToastModule } from 'primeng/toast';
import { MenuModule } from 'primeng/menu';
import { RouterLink } from '@angular/router';
import { MenuItem, MessageService } from 'primeng/api';
import { LoginComponent } from '../../core/auth/login/login.component';

interface AutoCompleteCompleteEvent {
  originalEvent: Event;
  query: string;
}

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [
            ButtonModule,
            AutoCompleteModule,
            FormsModule,
            MenuModule,
            RouterLink,
            ToastModule,
            LoginComponent
          ],
  providers: [MessageService],
  templateUrl: './home.component.html',
  styleUrl: './home.component.css'
})

export class HomeComponent implements OnInit {
  items: any[] | undefined;

  selectedItem: any;

  suggestions: any[] | undefined;

  search(event: AutoCompleteCompleteEvent) {
      this.suggestions = [...Array(10).keys()].map(item => event.query + '-' + item);
  }

  menuItems: MenuItem[] | undefined;

    constructor(private messageService: MessageService) {}
    
    ngOnInit() {
        this.menuItems = [
            {
                label: 'Options',
                menuItems: [
                    {
                        label: 'Update',
                        icon: 'pi pi-refresh',
                        command: () => {
                            this.update();
                        }
                    },
                    {
                        label: 'Delete',
                        icon: 'pi pi-times',
                        command: () => {
                            this.delete();
                        }
                    }
                ]
            },
            {
                label: 'Navigate',
                menuItems: [
                    {
                        label: 'Angular',
                        icon: 'pi pi-external-link',
                        url: 'http://angular.io'
                    },
                    {
                        label: 'Router',
                        icon: 'pi pi-upload',
                        routerLink: '/fileupload'
                    }
                ]
            }
        ];
    }

    update() {
        this.messageService.add({ severity: 'success', summary: 'Success', detail: 'Data Updated' });
    }

    delete() {
        this.messageService.add({ severity: 'warn', summary: 'Delete', detail: 'Data Deleted' });
    }
}
