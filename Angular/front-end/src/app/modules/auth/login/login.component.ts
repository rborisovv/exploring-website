import { Component, OnInit, Renderer2 } from '@angular/core';
import { faEnvelopeOpenText, faMessage, faMobileScreenButton, IconDefinition } from "@fortawesome/free-solid-svg-icons";
import { FormControl, FormGroup, Validators } from "@angular/forms";

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {
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

  constructor(private renderer: Renderer2) {
  }

  ngOnInit(): void {

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
}
