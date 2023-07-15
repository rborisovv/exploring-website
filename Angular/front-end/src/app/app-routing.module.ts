import { NgModule } from '@angular/core';
import { PreloadAllModules, RouterModule, Routes } from '@angular/router';
import { FontAwesomeModule } from "@fortawesome/angular-fontawesome";
import { HomeComponent } from "./modules/home/home/home.component";

const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'home' },
  { path: 'home', component: HomeComponent },
  { path: 'auth', loadChildren: () => import('./modules/auth/auth.module').then(m => m.AuthModule) }
];

@NgModule({
  imports: [
    RouterModule.forRoot(routes, {
      scrollPositionRestoration: "top",
      preloadingStrategy: PreloadAllModules,
      enableTracing: true
    }),
    FontAwesomeModule
  ],
  exports: [RouterModule]
})
export class AppRoutingModule {
}
