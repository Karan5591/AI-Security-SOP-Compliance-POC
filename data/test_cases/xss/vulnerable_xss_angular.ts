// Vulnerable: violates XSS-001 (bypasses Angular's sanitization on user-controlled content)
import { Component } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

@Component({
  selector: 'app-comment',
  template: `<div [innerHTML]="renderedComment"></div>`
})
export class CommentComponent {
  renderedComment: any;

  constructor(private sanitizer: DomSanitizer) {}

  setComment(userComment: string) {
    this.renderedComment = this.sanitizer.bypassSecurityTrustHtml(userComment);
  }
}
