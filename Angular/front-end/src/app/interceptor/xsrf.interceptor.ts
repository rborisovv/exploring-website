import { Injectable } from "@angular/core";
import { HttpEvent, HttpHandler, HttpInterceptor, HttpRequest } from "@angular/common/http";
import { Observable } from "rxjs";

@Injectable()
export class XsrfInterceptor implements HttpInterceptor {
  private static readonly accessToken: string = 'X-Access-Token';

  intercept(httpRequest: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const csrfToken: string = 'XSRF-TOKEN';

    return next.handle(httpRequest.clone({
      setHeaders: {
        'X-XSRF-TOKEN': XsrfInterceptor.obtainCsrfHeader(csrfToken),
        'X-Access-Token': XsrfInterceptor.obtainJwtHeader()
      }
    }));
  }

  private static obtainJwtHeader(): string {
    const value: string = `; ${document.cookie}`;
    const parts: string[] = value.split(`; ${this.accessToken}=`);
    return 'Bearer ' + parts.pop()?.split(';').shift();
  }

  private static obtainCsrfHeader(name: string): any {
    const value: string = `; ${document.cookie}`;
    const parts: string[] = value.split(`; ${name}=`);
    return parts.pop()?.split(';').shift();
  }
}
