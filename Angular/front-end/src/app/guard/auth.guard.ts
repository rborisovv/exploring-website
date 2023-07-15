import { CanActivateFn, Router } from '@angular/router';
import { inject } from "@angular/core";
import { CookieService } from "ngx-cookie-service";

export const authGuard: CanActivateFn = (): boolean => {
  const cookieService: CookieService = inject(CookieService);
  const router: Router = inject(Router);

  const isAuthenticated: boolean = cookieService.check('access_token');

  if (isAuthenticated) {
    router.navigate(['/home']);
    return false;
  }

  return true;
};
