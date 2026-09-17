// Vulnerable: violates BAC-003 (client-side check is the ONLY access control -
// the DELETE endpoint this calls has no server-side authorization check either)
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
  isAdmin = this.authService.getCurrentUser().role === 'admin'; // hides the button, nothing more

  constructor(private http: HttpClient, private authService: AuthService) {}

  deleteUser(userId: string) {
    this.http.delete(`/api/users/${userId}`).subscribe();
  }
}
