import { Component, OnInit } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { ActivatedRoute } from '@angular/router';

// Déclaration globale pour jQuery (si présent)
declare const $: any;  // <-- Cette ligne NE doit PAS être commentée

@Component({
  selector: 'app-xss',
  template: `
    <div class="vulnerability-container">
      <h2>XSS Vulnerabilities (Détectable par SAST)</h2>
      
      <div class="demo-section">
        <h3>1. innerHTML Direct</h3>
        <input [(ngModel)]="userInput" placeholder="Entrez du HTML (ex: <img src=x onerror=alert(1)>)">
        <button (click)="injectViaInnerHTML()">Injecter</button>
        <div id="innerHTML-output" class="output"></div>
      </div>

      <div class="demo-section">
        <h3>2. bypassSecurityTrustHtml</h3>
        <input [(ngModel)]="htmlInput" placeholder="Entrez du HTML">
        <button (click)="bypassSecurity()">Bypass Security</button>
        <div [innerHTML]="trustedHtml" class="output"></div>
      </div>

      <div class="demo-section">
        <h3>3. document.write</h3>
        <input [(ngModel)]="writeInput" placeholder="Contenu pour document.write">
        <button (click)="useDocumentWrite()">Document Write</button>
      </div>

      <div class="demo-section">
        <h3>4. DOM XSS via URL</h3>
        <p>Paramètre URL actuel: {{urlParam}}</p>
        <div id="url-output" class="output"></div>
      </div>

      <div class="demo-section">
        <h3>5. jQuery HTML (si disponible)</h3>
        <button (click)="jqueryInject()">Test jQuery</button>
        <div id="jquery-output" class="output"></div>
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
    .output {
      margin-top: 10px;
      padding: 10px;
      background: #f5f5f5;
      min-height: 30px;
    }
    input {
      padding: 5px;
      margin-right: 10px;
      width: 300px;
    }
    button {
      padding: 5px 15px;
      cursor: pointer;
    }
  `]
})
export class XssComponent implements OnInit {
  userInput = '';
  htmlInput = '';
  writeInput = '';
  trustedHtml: SafeHtml = '';
  urlParam = '';

  constructor(
    private sanitizer: DomSanitizer,
    private route: ActivatedRoute
  ) {}

  ngOnInit() {
    // VULNÉRABLE: DOM XSS via query params - DÉTECTÉ par SAST
    this.route.queryParams.subscribe(params => {
      this.urlParam = params['q'] || '';
      if (this.urlParam) {
        // FLAG: Direct innerHTML avec paramètre URL
        const element = document.getElementById('url-output');
        if (element) {
          element.innerHTML = `Recherche: ${this.urlParam}`;
        }
      }
    });

    // VULNÉRABLE: DOM XSS via location.hash - DÉTECTÉ
    window.addEventListener('hashchange', () => {
      const hash = location.hash.substring(1);
      document.getElementById('url-output')!.innerHTML = decodeURIComponent(hash);
    });
  }

  // VULNÉRABLE: innerHTML direct - DÉTECTÉ
  injectViaInnerHTML() {
    const element = document.getElementById('innerHTML-output');
    if (element) {
      // FLAG: Direct innerHTML assignment
      element.innerHTML = this.userInput;
    }
  }

  // VULNÉRABLE: bypassSecurityTrustHtml - DÉTECTÉ
  bypassSecurity() {
    // FLAG: Bypass Angular security
    this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(this.htmlInput);
  }

  // VULNÉRABLE: document.write - DÉTECTÉ
  useDocumentWrite() {
    // FLAG: document.write usage
    document.write(this.writeInput);
  }

  // VULNÉRABLE: jQuery html() - DÉTECTÉ si jQuery présent
  jqueryInject() {
    
    if (typeof $ !== 'undefined') {
      // FLAG: jQuery html with user input
      $('#jquery-output').html(this.userInput);
    } else {
      // Fallback sans jQuery mais toujours vulnérable
      const element = document.getElementById('jquery-output');
      if (element) {
        element.innerHTML = 'jQuery non disponible, mais voici le contenu: ' + this.userInput;
      }
    }
  }

  // VULNÉRABLE: insertAdjacentHTML - DÉTECTÉ
  insertAdjacent() {
    document.body.insertAdjacentHTML('beforeend', this.userInput);
  }

  // VULNÉRABLE: outerHTML - DÉTECTÉ
  replaceElement() {
    const element = document.getElementById('innerHTML-output');
    if (element) {
      // FLAG: outerHTML assignment
      element.outerHTML = `<div>${this.userInput}</div>`;
    }
  }
}