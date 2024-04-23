import { ApplicationConfig } from '@angular/core';
import { provideRouter, withComponentInputBinding, withViewTransitions } from '@angular/router';

import { routes } from './app.routes';
import { LogInterceptor } from './helpers/logInterceptor';
import { provideClientHydration } from '@angular/platform-browser';
import { HTTP_INTERCEPTORS, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';
import { JWT_OPTIONS, JwtHelperService } from '@auth0/angular-jwt';
import { JwtInterceptor } from './helpers/JwtInterceptor';
import { provideAnimations } from '@angular/platform-browser/animations';

export const appConfig: ApplicationConfig = {
    providers: [
        provideRouter(routes, withComponentInputBinding(), withViewTransitions()),
        provideClientHydration(),
        provideAnimations(),
        provideHttpClient(withInterceptorsFromDi()),
        { provide: JWT_OPTIONS, useValue: JWT_OPTIONS },
        JwtHelperService,
        { provide: HTTP_INTERCEPTORS, useClass: JwtInterceptor, multi: true },
        { provide: HTTP_INTERCEPTORS, useClass: LogInterceptor, multi: true },
    ],
};
