import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { FontAwesomeModule } from "@fortawesome/angular-fontawesome";

const routes: Routes = [
  { path: 'auth', loadChildren: () => import('./modules/auth/auth.module').then(m => m.AuthModule) }
];

@NgModule({
  imports: [
    RouterModule.forRoot(routes),
    FontAwesomeModule
  ],
  exports: [RouterModule]
})
export class AppRoutingModule {
}
