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
import { FormControl, FormGroup, Validators } from "@angular/forms";
import { faMessage } from "@fortawesome/free-regular-svg-icons";

import { GdprSectionsEnum } from "../../../model/auth/gdpr.sections.enum";

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss'],
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class LoginComponent implements OnInit {
  protected readonly GdprSectionsEnum = GdprSectionsEnum;

  gdprModalOpened: boolean = false;
  gdprConsents: Array<string> = [];

  @ViewChild('gdprModalBody') gdprModal?: ElementRef;

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
    ]),
    gdprConsent: new FormControl([], [])
  });

  constructor(private renderer: Renderer2) {
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

    }
    this.gdprModalOpened = true;
  }

  protected applyConsentToGdprSection(event: MouseEvent, section: GdprSectionsEnum): void {
    const gdprElement: HTMLDivElement | null = (<HTMLElement>event.target).closest('.settings-button-container');

    const gdprIconContainer: HTMLDivElement = gdprElement?.querySelector('div.app-settings-button-icon') as HTMLDivElement;
    const gdprButton: HTMLButtonElement = gdprElement?.querySelector('button.app-settings-button') as HTMLButtonElement;

    this.toggleClass(gdprIconContainer, 'settings-button-icon-active');
    this.toggleClass(gdprButton, 'settings-button-active');

    const sectionIndex: number = this.gdprConsents.indexOf(section);
    sectionIndex === -1 ? this.gdprConsents.push(section) : this.gdprConsents.splice(sectionIndex, 1);
  }
}
