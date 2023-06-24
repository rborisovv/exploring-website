import { Injectable } from '@angular/core';
import { HttpClient } from "@angular/common/http";
import { Observable } from "rxjs";
import { UserLoginModel } from "../model/auth/user.login.model";

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private API_URL: string = 'http://localhost:8080';

  constructor(private http: HttpClient) {
  }

  public loginUser(loginModel: UserLoginModel): Observable<UserLoginModel> {
    return this.http.post<UserLoginModel>(this.API_URL, loginModel);
  }
}
