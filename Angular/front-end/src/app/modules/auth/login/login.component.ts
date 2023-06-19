import { Component, OnInit, Renderer2 } from '@angular/core';
import { faEnvelopeOpenText, faMessage, faMobileScreenButton, IconDefinition } from "@fortawesome/free-solid-svg-icons";

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {
  mobileScreen: IconDefinition = faMobileScreenButton;
  envelope: IconDefinition = faEnvelopeOpenText;
  message: IconDefinition = faMessage;

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

  protected readonly faMessage = faMessage;

  decorateActiveInput(event: Event): void {
    const input: HTMLInputElement = (event.target) as HTMLInputElement;
    const inputContainer: HTMLDivElement | null = input.closest('.app-input');

    if (!input.value && inputContainer) {
      this.toggleClass(inputContainer, 'input-active');
    }
  }
}
