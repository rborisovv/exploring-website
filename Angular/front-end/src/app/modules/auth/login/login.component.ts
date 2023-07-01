import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  HostListener,
  OnInit,
  Renderer2,
  ViewChild
} from '@angular/core';
import { faEnvelopeOpenText, faMobileScreenButton, IconDefinition } from "@fortawesome/free-solid-svg-icons";
import { AbstractControl, FormControl, FormGroup, Validators } from "@angular/forms";
import { faMessage } from "@fortawesome/free-regular-svg-icons";

import { GdprSectionsEnum } from "../../../model/auth/gdpr.sections.enum";
import { AuthService } from "../../../services/auth.service";
import { UserLoginModel } from "../../../model/auth/user.login.model";
import { GdprSectionsModel } from "../../../model/auth/gdpr.sections.model";
import { take } from "rxjs";
import { Router } from "@angular/router";

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss'],
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class LoginComponent implements OnInit {
  protected readonly GdprSectionsEnum = GdprSectionsEnum;

  gdprModalOpened: boolean = false;
  private gdprConsents: GdprSectionsModel = {};

  @ViewChild('gdprModalBody') gdprModal: ElementRef;

  mobileScreen: IconDefinition = faMobileScreenButton;
  envelope: IconDefinition = faEnvelopeOpenText;
  message: IconDefinition = faMessage;

  loginFormGroup: FormGroup = new FormGroup({
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

  ngOnInit(): void {

  }

  @HostListener('document:click', ['$event'])
  onDocumentClick(event: MouseEvent): void {
    if (!this.gdprModal?.nativeElement.contains(event.target)) {
      this.gdprModalOpened = false;
    }
  }

  private toggleClass(element: HTMLElement, className: string): void {
    const isActive: boolean = element.classList.contains(className);

    if (isActive) {
      this.renderer.removeClass(element, className);
    } else {
      this.renderer.addClass(element, className);
    }
  }

  decorateActiveInput(event: Event): void {
    const input: HTMLInputElement = (event.target) as HTMLInputElement;
    const inputContainer: HTMLDivElement | null = input.closest('.app-input');

    if (!input.value && inputContainer) {
      this.toggleClass(inputContainer, 'input-active');
    }
  }

  protected submitLogin(): void {
    if (this.loginFormGroup.invalid) {
      this.loginFormGroup.markAllAsTouched();
      return;
    }
    this.gdprModalOpened = true;
  }

  protected applyConsentToGdprSection(event: MouseEvent, section: GdprSectionsEnum): void {
    const gdprElement: HTMLDivElement | null = (<HTMLElement>event.target).closest('.settings-button-container');
    const gdprIconContainer: HTMLDivElement = gdprElement?.querySelector('div.app-settings-button-icon') as HTMLDivElement;
    const gdprButton: HTMLButtonElement = gdprElement?.querySelector('button.app-settings-button') as HTMLButtonElement;

    this.toggleClass(gdprIconContainer, 'settings-button-icon-active');
    this.toggleClass(gdprButton, 'settings-button-active');

    switch (section) {
      case GdprSectionsEnum.PUSH:
        this.gdprConsents.push = !this.gdprConsents.push;
        break;
      case GdprSectionsEnum.EMAIL:
        this.gdprConsents.email = !this.gdprConsents.email;
        break;
      case GdprSectionsEnum.SMS:
        this.gdprConsents.sms = !this.gdprConsents.sms;
        break;
    }
  }

  get username(): AbstractControl | null {
    return this.loginFormGroup.get('username');
  }

  get password(): AbstractControl | null {
    return this.loginFormGroup.get('password');
  }

  loginUser(): void {
    if (this.loginFormGroup.invalid) {
      return;
    }

    const loginData: UserLoginModel = {
      username: this.username?.value,
      password: this.password?.value,
      gdprConsent: this.gdprConsents
    }

    this.authService.loginUser(loginData).pipe(
      take(1))
      .subscribe(() => {
        this.router.navigate(['/']);
      });
  }
}
