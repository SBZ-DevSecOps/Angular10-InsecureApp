import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';

@Component({
  selector: 'app-redirect',
  template: `
    <div class="vulnerability-container">
      <h2>Open Redirect (Détectable par SAST)</h2>
      
      <div class="demo-section">
        <h3>1. window.location.href</h3>
        <input [(ngModel)]="redirectUrl" placeholder="Ex: https://evil.com">
        <button (click)="redirectHref()">Rediriger (href)</button>
      </div>

      <div class="demo-section">
        <h3>2. location.assign</h3>
        <input [(ngModel)]="assignUrl" placeholder="Ex: https://malicious.com">
        <button (click)="redirectAssign()">Rediriger (assign)</button>
      </div>

      <div class="demo-section">
        <h3>3. window.open</h3>
        <input [(ngModel)]="openUrl" placeholder="URL à ouvrir">
        <button (click)="openWindow()">Ouvrir nouvelle fenêtre</button>
      </div>

      <div class="demo-section">
        <h3>4. Meta Refresh</h3>
        <input [(ngModel)]="metaUrl" placeholder="URL pour meta refresh">
        <button (click)="metaRedirect()">Meta Redirect</button>
      </div>

      <div class="demo-section">
        <h3>5. Form Action Dynamique</h3>
        <input [(ngModel)]="formUrl" placeholder="URL du formulaire">
        <button (click)="createRedirectForm()">Créer Form Redirect</button>
      </div>

      <div class="demo-section">
        <h3>6. Lien Dynamique</h3>
        <input [(ngModel)]="linkUrl" placeholder="URL du lien">
        <button (click)="updateLink()">Mettre à jour le lien</button>
        <a id="dynamic-link" href="#">Lien dynamique</a>
      </div>

      <div class="demo-section">
        <h3>7. Redirect depuis URL params</h3>
        <p>URL actuelle: {{currentUrl}}</p>
        <p>Param returnUrl: {{returnUrlParam}}</p>
        <button (click)="checkUrlParams()">Vérifier params</button>
      </div>

      <div class="demo-section">
        <h3>8. Crypto Faible</h3>
        <button (click)="generateWeakToken()">Générer Token</button>
        <p>Token: {{weakToken}}</p>
        <button (click)="generateWeakSession()">Générer Session ID</button>
        <p>Session: {{weakSession}}</p>
      </div>
    </div>
  `,
  styles: [`
    .vulnerability-container {
      padding: 20px;
    }
    .demo-section {
      margin: 20px 0;
      padding: 15px;
      border: 1px solid #ddd;
      border-radius: 5px;
    }
    input {
      padding: 5px;
      margin-right: 10px;
      width: 300px;
    }
    button {
      padding: 5px 15px;
      cursor: pointer;
      margin-right: 10px;
    }
    a {
      display: inline-block;
      margin-top: 10px;
      color: blue;
    }
  `]
})
export class RedirectComponent implements OnInit {
  redirectUrl = '';
  assignUrl = '';
  openUrl = '';
  metaUrl = '';
  formUrl = '';
  linkUrl = '';
  
  currentUrl = '';
  returnUrlParam = '';
  
  weakToken = '';
  weakSession = '';

  constructor(
    private route: ActivatedRoute,
    private router: Router
  ) {}

  ngOnInit() {
    this.currentUrl = window.location.href;
    
    // VULNÉRABLE: Redirect depuis query params - DÉTECTÉ
    this.route.queryParams.subscribe(params => {
      this.returnUrlParam = params['returnUrl'] || params['redirect'] || '';
      
      if (this.returnUrlParam) {
        // FLAG: Open redirect via location.href
        window.location.href = this.returnUrlParam;
      }
    });
    
    // VULNÉRABLE: Redirect depuis hash - DÉTECTÉ
    if (location.hash.includes('redirect=')) {
      const url = location.hash.split('redirect=')[1];
      window.location.href = decodeURIComponent(url);
    }
  }

  // VULNÉRABLE: window.location.href - DÉTECTÉ
  redirectHref() {
    // FLAG: Unvalidated redirect
    window.location.href = this.redirectUrl;
  }

  // VULNÉRABLE: location.assign - DÉTECTÉ
  redirectAssign() {
    // FLAG: Unvalidated location.assign
    window.location.assign(this.assignUrl);
  }

  // VULNÉRABLE: location.replace - DÉTECTÉ
  redirectReplace() {
    // FLAG: Unvalidated location.replace
    window.location.replace(this.redirectUrl);
  }

  // VULNÉRABLE: window.open - DÉTECTÉ
  openWindow() {
    // FLAG: Unvalidated window.open
    window.open(this.openUrl, '_blank');
  }

  // VULNÉRABLE: Meta refresh - DÉTECTÉ
  metaRedirect() {
    const meta = document.createElement('meta');
    // FLAG: Meta refresh with user input
    meta.httpEquiv = 'refresh';
    meta.content = `0; url=${this.metaUrl}`;
    document.head.appendChild(meta);
  }

  // VULNÉRABLE: Form action dynamique - DÉTECTÉ
  createRedirectForm() {
    const form = document.createElement('form');
    // FLAG: Dynamic form action
    form.action = this.formUrl;
    form.method = 'GET';
    form.id = 'redirect-form';
    
    document.body.appendChild(form);
    form.submit();
  }

  // VULNÉRABLE: Lien href dynamique - DÉTECTÉ
  updateLink() {
    const link = document.getElementById('dynamic-link') as HTMLAnchorElement;
    if (link) {
      // FLAG: Unvalidated href assignment
      link.href = this.linkUrl;
    }
  }

  // VULNÉRABLE: Router Angular avec URL externe - Pattern détecté
  redirectWithRouter() {
    // FLAG: Router navigation with external URL
    this.router.navigateByUrl(this.redirectUrl);
  }

  checkUrlParams() {
    // Re-check les params
    const urlParams = new URLSearchParams(window.location.search);
    const redirect = urlParams.get('redirect');
    if (redirect) {
      window.location.href = redirect;
    }
  }

  // VULNÉRABLE: Math.random pour token - DÉTECTÉ
  generateWeakToken() {
    // FLAG: Math.random used for security token
    this.weakToken = Math.random().toString(36).substring(2, 15);
  }

  // VULNÉRABLE: Session ID prévisible - DÉTECTÉ
  generateWeakSession() {
    // FLAG: Predictable session ID
    const timestamp = Date.now();
    const random = Math.floor(Math.random() * 1000);
    this.weakSession = `session_${timestamp}_${random}`;
  }

  // VULNÉRABLE: Math.random pour password - DÉTECTÉ
  generateWeakPassword(): string {
    // FLAG: Weak password generation
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let password = '';
    for (let i = 0; i < 8; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
  }
}