import { APP_INITIALIZER, NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { TranslateLoader, TranslateModule } from "@ngx-translate/core";
import { HTTP_INTERCEPTORS, HttpClient, HttpClientModule, HttpClientXsrfModule } from "@angular/common/http";
import { TranslateHttpLoader } from "@ngx-translate/http-loader";
import { catchError, Observable, of } from "rxjs";
import { HttpHeadersDecoratorInterceptor } from "./interceptor/http.headers.decorator.interceptor";
import { XsrfInterceptor } from "./interceptor/xsrf.interceptor";

export function fetchCsrfToken(httpClient: HttpClient): () => Observable<any> {
  return () => httpClient.get('http://localhost:8080/auth/csrf').pipe(catchError(() => of(null)));
}

export function HttpLoaderFactory(http: HttpClient): TranslateHttpLoader {
  return new TranslateHttpLoader(http);
}

@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    TranslateModule.forRoot({
      defaultLanguage: "en",
      loader: {
        provide: TranslateLoader,
        useFactory: HttpLoaderFactory,
        deps: [HttpClient]
      }
    }),
    HttpClientXsrfModule
  ],
  providers: [
    {
      provide: APP_INITIALIZER,
      useFactory: fetchCsrfToken,
      deps: [HttpClient],
      multi: true
    },
    {
      provide: HTTP_INTERCEPTORS,
      useClass: HttpHeadersDecoratorInterceptor,
      multi: true
    },
    {
      provide: HTTP_INTERCEPTORS,
      useClass: XsrfInterceptor,
      multi: true
    }
  ],
  bootstrap: [AppComponent]
})
export class AppModule {
}
