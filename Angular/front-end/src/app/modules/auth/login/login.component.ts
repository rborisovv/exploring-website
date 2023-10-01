import {
  ChangeDetectionStrategy,
  Component, Renderer2
} from '@angular/core';
import { FormControl, FormGroup, Validators } from "@angular/forms";
import { faUser, IconDefinition } from "@fortawesome/free-solid-svg-icons";
import { faLock } from "@fortawesome/free-solid-svg-icons/faLock";
import { AuthService } from "../../../services/auth.service";
import { UserLoginModel } from "../../../model/auth/user.login.model";
import { UntilDestroy, untilDestroyed } from "@ngneat/until-destroy";
import { Router } from "@angular/router";

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss'],
  changeDetection: ChangeDetectionStrategy.OnPush
})
@UntilDestroy()
export class LoginComponent {
  user: IconDefinition = faUser;
  lock: IconDefinition = faLock;

  loginFormGroup = new FormGroup({
    username: new FormControl('', [
      Validators.required,
      Validators.minLength(5),
      Validators.maxLength(10)
    ]),
    password: new FormControl('', [
      Validators.required,
      Validators.minLength(6),
      Validators.maxLength(20)
    ])
  });

  constructor(private renderer: Renderer2,
              private authService: AuthService,
              private router: Router) {
  }

  onInputFocus(inputContainer: HTMLDivElement): void {
    this.renderer.addClass(inputContainer, 'focus');
  }

  onInputBlur(inputContainer: HTMLDivElement, event: Event): void {
    const input: HTMLInputElement = event.target as HTMLInputElement;

    if (input.value === "") {
      this.renderer.removeClass(inputContainer, 'focus');
    }
  }

  get username(): string | null | undefined {
    return this.loginFormGroup.get('username')?.value;
  }

  get password(): string | null | undefined {
    return this.loginFormGroup.get('password')?.value;
  }

  login(): void {
    const userLoginModel: UserLoginModel = this.collectLoginData();
    this.authService.loginUser(userLoginModel)
      .pipe(untilDestroyed(this))
      .subscribe((): void => {
        this.router.navigate(['/home']);
      });
  }

  private collectLoginData(): UserLoginModel {
    const loginData: UserLoginModel = {};

    if (this.username) {
      loginData.username = this.username;
    }

    if (this.password) {
      loginData.password = this.password;
    }

    return loginData;
  }
}
