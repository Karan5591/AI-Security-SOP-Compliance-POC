// Secure: relies on Angular's default sanitization, satisfies XSS-001
import { Component } from '@angular/core';

@Component({
  selector: 'app-comment',
  template: `<div>{{ userComment }}</div>` // interpolation, not [innerHTML] - Angular escapes this
})
export class CommentComponent {
  userComment: string;

  setComment(userComment: string) {
    this.userComment = userComment; // no bypass, rendered as plain text
  }
}
