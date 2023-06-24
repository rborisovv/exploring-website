import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LoginComponent } from './login/login.component';
import { RouterModule, Routes } from "@angular/router";
import { FontAwesomeModule } from "@fortawesome/angular-fontawesome";
import { ReactiveFormsModule } from "@angular/forms";
import { TranslateModule } from "@ngx-translate/core";

const ROUTES: Routes = [
  {
    path: '', children: [
      { path: 'login', title: 'WanderSnap | Login', component: LoginComponent }
    ]
  }
];

@NgModule({
  declarations: [
    LoginComponent
  ],
    imports: [
        CommonModule,
        RouterModule.forChild(ROUTES),
        FontAwesomeModule,
        ReactiveFormsModule,
        TranslateModule
    ],
  providers: []
})
export class AuthModule {
}
