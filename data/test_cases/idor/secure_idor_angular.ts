// Secure: UI hiding the button is still just a convenience (satisfies BAC-003) -
// what actually satisfies it is that the DELETE endpoint independently enforces
// authorization server-side (see idor/secure_idor.js), so a forged request from
// a non-admin still gets rejected with 403 regardless of what the UI shows.
import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Component({
  selector: 'app-admin-panel',
  template: `
    <button *ngIf="isAdmin" (click)="deleteUser(userId)">Delete User</button>
  `
})
export class AdminPanelComponent {
  userId: string;
  isAdmin = this.authService.getCurrentUser().role === 'admin'; // UI convenience only, not a security boundary

  constructor(private http: HttpClient, private authService: AuthService) {}

  deleteUser(userId: string) {
    this.http.delete(`/api/users/${userId}`).subscribe({
      error: (err) => this.handleForbidden(err) // backend returns 403 if the caller isn't actually authorized
    });
  }

  private handleForbidden(err: unknown) {
    // surface an error toast, etc.
  }
}
