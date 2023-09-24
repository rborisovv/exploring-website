import {
  ChangeDetectionStrategy,
  Component,
  OnInit, Renderer2
} from '@angular/core';
import { FormControl, FormGroup, Validators } from "@angular/forms";
import { faUser, IconDefinition } from "@fortawesome/free-solid-svg-icons";
import { faLock } from "@fortawesome/free-solid-svg-icons/faLock";

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss'],
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class LoginComponent implements OnInit {
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

  constructor(private renderer: Renderer2) {
  }

  ngOnInit(): void {

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
}
