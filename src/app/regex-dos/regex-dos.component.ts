import { Component } from '@angular/core';

@Component({
  selector: 'app-regex-dos',
  template: `
    <div class="vulnerability-container">
      <h2>ReDoS Vulnerabilities (Détectable par SAST)</h2>
      
      <div class="demo-section">
        <h3>1. Email Validation (Catastrophic Backtracking)</h3>
        <input [(ngModel)]="emailInput" placeholder="Ex: aaaaaaaaaaaaaaaaaaaaaa@">
        <button (click)="validateEmail()">Valider Email</button>
        <p>Résultat: {{emailResult}}</p>
        <p class="hint">Essayez: {{emailPayload}}</p>
      </div>

      <div class="demo-section">
        <h3>2. Pattern Imbriqué</h3>
        <input [(ngModel)]="nestedInput" placeholder="Ex: aaaaaaaaaaaaaaaaaaaaaa!">
        <button (click)="validateNested()">Valider</button>
        <p>Résultat: {{nestedResult}}</p>
      </div>

      <div class="demo-section">
        <h3>3. URL Validation</h3>
        <input [(ngModel)]="urlInput" placeholder="URL à valider">
        <button (click)="validateUrl()">Valider URL</button>
        <p>Résultat: {{urlResult}}</p>
      </div>

      <div class="demo-section">
        <h3>4. Password Complexity</h3>
        <input [(ngModel)]="passwordInput" type="password" placeholder="Password">
        <button (click)="validatePassword()">Valider Password</button>
        <p>Résultat: {{passwordResult}}</p>
      </div>

      <div class="demo-section">
        <h3>5. CSV Parser</h3>
        <input [(ngModel)]="csvInput" placeholder="Ex: a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a">
        <button (click)="parseCSV()">Parser CSV</button>
        <p>Résultat: {{csvResult}}</p>
      </div>

      <div class="demo-section">
        <h3>6. Custom Regex</h3>
        <input [(ngModel)]="customPattern" placeholder="Pattern regex">
        <input [(ngModel)]="customInput" placeholder="Texte à tester">
        <button (click)="testCustomRegex()">Tester</button>
        <p>Résultat: {{customResult}}</p>
      </div>

      <p class="warning">⚠️ Attention: Certains patterns peuvent faire freezer le navigateur!</p>
    </div>
  `,
  styles: [`
    .vulnerability-container { padding: 20px; }
    .demo-section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
    input { padding: 5px; margin-right: 10px; width: 300px; }
    button { padding: 5px 15px; cursor: pointer; }
    .hint { font-size: 12px; color: #666; font-family: monospace; }
    .warning { color: #d32f2f; font-weight: bold; margin-top: 20px; }
  `]
})
export class RegexDosComponent {
  emailInput = '';
  nestedInput = '';
  urlInput = '';
  passwordInput = '';
  csvInput = '';
  customPattern = '';
  customInput = '';
  
  emailResult = '';
  nestedResult = '';
  urlResult = '';
  passwordResult = '';
  csvResult = '';
  customResult = '';
  
  emailPayload = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@';

  // VULNÉRABLE: Email regex avec backtracking - DÉTECTÉ
  validateEmail() {
    // FLAG: ReDoS vulnerable regex (catastrophic backtracking)
    const regex = /^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+\.([a-zA-Z]+)+$/;
    
    const startTime = performance.now();
    try {
      this.emailResult = regex.test(this.emailInput) ? 'Valide' : 'Invalide';
    } catch (e) {
      this.emailResult = 'Erreur';
    }
    const endTime = performance.now();
    
    this.emailResult += ` (${Math.round(endTime - startTime)}ms)`;
  }

  // VULNÉRABLE: Quantificateurs imbriqués - DÉTECTÉ
  validateNested() {
    // FLAG: Nested quantifiers
    const regex = /^(([a-z]+)+)+$/;
    
    const startTime = performance.now();
    try {
      this.nestedResult = regex.test(this.nestedInput) ? 'Match' : 'No match';
    } catch (e) {
      this.nestedResult = 'Erreur';
    }
    const endTime = performance.now();
    
    this.nestedResult += ` (${Math.round(endTime - startTime)}ms)`;
  }

  // VULNÉRABLE: URL validation complexe - DÉTECTÉ
  validateUrl() {
    // FLAG: ReDoS in URL validation
    const regex = /^(https?:\/\/)?([\w\-]+\.)+[\w\-]+(\/[\w\-._~:/?#[\]@!$&'()*+,;=]*)?$/;
    
    const startTime = performance.now();
    try {
      this.urlResult = regex.test(this.urlInput) ? 'URL valide' : 'URL invalide';
    } catch (e) {
      this.urlResult = 'Erreur';
    }
    const endTime = performance.now();
    
    this.urlResult += ` (${Math.round(endTime - startTime)}ms)`;
  }

  // VULNÉRABLE: Password regex complexe - DÉTECTÉ
  validatePassword() {
    // FLAG: Complex password regex with ReDoS
    const regex = /^(?=.*[a-z]+)+(?=.*[A-Z]+)+(?=.*[0-9]+)+(?=.*[!@#$%^&*]+)+.{8,}$/;
    
    const startTime = performance.now();
    try {
      this.passwordResult = regex.test(this.passwordInput) ? 'Fort' : 'Faible';
    } catch (e) {
      this.passwordResult = 'Erreur';
    }
    const endTime = performance.now();
    
    this.passwordResult += ` (${Math.round(endTime - startTime)}ms)`;
  }

  // VULNÉRABLE: CSV parsing avec regex - DÉTECTÉ
  parseCSV() {
    // FLAG: ReDoS in CSV parsing
    const regex = /([^,]+)+,?/g;
    
    const startTime = performance.now();
    try {
      const matches = this.csvInput.match(regex);
      this.csvResult = `${matches?.length || 0} valeurs trouvées`;
    } catch (e) {
      this.csvResult = 'Erreur';
    }
    const endTime = performance.now();
    
    this.csvResult += ` (${Math.round(endTime - startTime)}ms)`;
  }

  // VULNÉRABLE: Regex dynamique - DÉTECTÉ
  testCustomRegex() {
    if (!this.customPattern) {
      this.customResult = 'Pattern requis';
      return;
    }
    
    try {
      // FLAG: Dynamic regex from user input
      const regex = new RegExp(this.customPattern);
      
      const startTime = performance.now();
      const result = regex.test(this.customInput);
      const endTime = performance.now();
      
      this.customResult = `${result ? 'Match' : 'No match'} (${Math.round(endTime - startTime)}ms)`;
    } catch (e) {
      this.customResult = 'Pattern invalide';
    }
  }

  // VULNÉRABLE: Autres patterns ReDoS - DÉTECTÉ
  
  // Alternation avec overlap
  validateAlternation(input: string): boolean {
    // FLAG: Overlapping alternation
    const regex = /^(a|a)*$/;
    return regex.test(input);
  }
  
  // Quantificateurs multiples
  validateMultiple(input: string): boolean {
    // FLAG: Multiple quantifiers
    const regex = /^(a+)+b$/;
    return regex.test(input);
  }
  
  // Format date vulnérable
  validateDate(date: string): boolean {
    // FLAG: Date validation ReDoS
    const regex = /^(\d{1,2})+[\/\-](\d{1,2})+[\/\-](\d{4})+$/;
    return regex.test(date);
  }
  
  // Replace avec regex complexe
  sanitizeInput(input: string): string {
    // FLAG: ReDoS in replace operation
    return input.replace(/([a-z]+)+$/g, '');
  }
  
  // Split avec regex vulnérable
  splitInput(input: string): string[] {
    // FLAG: ReDoS in split
    const regex = /([,;])+\s*/;
    return input.split(regex);
  }
}