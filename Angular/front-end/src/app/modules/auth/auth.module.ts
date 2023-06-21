import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LoginComponent } from './login/login.component';
import { RouterModule, Routes } from "@angular/router";
import { FontAwesomeModule } from "@fortawesome/angular-fontawesome";
import { ReactiveFormsModule } from "@angular/forms";

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
    ReactiveFormsModule
  ],
  providers: []
})
export class AuthModule {
}
