import { GdprSectionsModel } from "./gdpr.sections.model";

export interface UserLoginModel {
  username: string,
  password: string,
  gdprConsent: GdprSectionsModel
}
