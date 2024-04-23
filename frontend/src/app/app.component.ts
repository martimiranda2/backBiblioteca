import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { HomeComponent } from './modules/home/home.component';
import { DashboardComponent } from './modules/dashboard/dashboard.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
            RouterOutlet,
            HomeComponent,
            DashboardComponent
          ],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent {
  title = 'frontend';
}
