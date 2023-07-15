import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor, HttpErrorResponse
} from '@angular/common/http';
import { catchError, Observable, of, throwError } from 'rxjs';
import { Router } from "@angular/router";
import { CookieService } from "ngx-cookie-service";

@Injectable()
export class UnauthorizedInterceptor implements HttpInterceptor {
  private accessTokenCookie: string = 'access_token';

  constructor(private router: Router,
              private cookieService: CookieService) {
  }

  private handleAuthError(err: HttpErrorResponse): Observable<any> {
    if (err.status === 401 || err.status === 403) {
      this.router.navigate(['/auth/login'])
        .then((): void => {
          this.cookieService.delete(this.accessTokenCookie);
        });
      return of(err.message);
    }
    return throwError((): void => {
      new Error(err.message);
    });
  }

  intercept(req: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    return next.handle(req).pipe(catchError((x) => this.handleAuthError(x)));
  }
}
