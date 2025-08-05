import { Component } from '@angular/core';

@Component({
  selector: 'app-storage',
  template: `
    <div class="vulnerability-container">
      <h2>Stockage Non Sécurisé (Détectable par SAST)</h2>
      
      <div class="demo-section">
        <h3>1. Mots de passe en localStorage</h3>
        <input #password type="password" placeholder="Mot de passe">
        <button (click)="storePassword(password.value)">Sauvegarder</button>
        <p>Valeur stockée: {{getStoredPassword()}}</p>
      </div>

      <div class="demo-section">
        <h3>2. Tokens d'authentification</h3>
        <input #token placeholder="Token JWT">
        <button (click)="storeAuthToken(token.value)">Sauvegarder Token</button>
        <p>Token actuel: {{getStoredToken()}}</p>
      </div>

      <div class="demo-section">
        <h3>3. Données bancaires</h3>
        <input #card placeholder="Numéro de carte">
        <input #cvv placeholder="CVV">
        <button (click)="storeCreditCard(card.value, cvv.value)">Sauvegarder</button>
      </div>

      <div class="demo-section">
        <h3>4. Secrets en dur dans le code</h3>
        <button (click)="exposeSecrets()">Afficher les secrets</button>
        <pre *ngIf="showSecrets">{{secrets | json}}</pre>
      </div>

      <div class="demo-section">
        <h3>5. Console.log de données sensibles</h3>
        <button (click)="logSensitiveData()">Log données sensibles</button>
        <p>Ouvrez la console pour voir les logs</p>
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
      width: 200px;
    }
    button {
      padding: 5px 15px;
      cursor: pointer;
    }
    pre {
      background: #f5f5f5;
      padding: 10px;
      overflow: auto;
    }
  `]
})
export class StorageComponent {
  showSecrets = false;

  // VULNÉRABLE: Secrets en dur - DÉTECTÉ par Snyk, SonarQube, GitGuardian
  private apiKey = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';
  private apiSecret = 'secret_key_abcdef123456';
  private dbPassword = 'admin123!@#';
  
  // VULNÉRABLE: AWS Credentials - DÉTECTÉ
  private awsAccessKey = 'AKIAIOSFODNN7EXAMPLE';
  private awsSecretKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  
  // VULNÉRABLE: Tokens - DÉTECTÉ
  private githubToken = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';
  private slackWebhook = 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX';

  // VULNÉRABLE: Clés privées - DÉTECTÉ
  private privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF32TpPQ
-----END RSA PRIVATE KEY-----`;

  get secrets() {
    return {
      apiKey: this.apiKey,
      awsAccessKey: this.awsAccessKey,
      githubToken: this.githubToken,
      dbPassword: this.dbPassword
    };
  }

  // VULNÉRABLE: Stockage de mot de passe - DÉTECTÉ
  storePassword(password: string) {
    // FLAG: Password in localStorage
    localStorage.setItem('userPassword', password);
    localStorage.setItem('password', password);
    
    // FLAG: Password in sessionStorage
    sessionStorage.setItem('tempPassword', password);
    
    // FLAG: Password in cookie
    document.cookie = `password=${password}`;
  }

  // VULNÉRABLE: Stockage de token - DÉTECTÉ
  storeAuthToken(token: string) {
    // FLAG: Auth token in localStorage (should be httpOnly cookie)
    localStorage.setItem('authToken', token);
    localStorage.setItem('jwtToken', token);
    localStorage.setItem('bearerToken', token);
    localStorage.setItem('accessToken', token);
    localStorage.setItem('api_token', token);
    
    // FLAG: Token in sessionStorage
    sessionStorage.setItem('sessionToken', token);
  }

  // VULNÉRABLE: Stockage de données bancaires - DÉTECTÉ
  storeCreditCard(cardNumber: string, cvv: string) {
    // FLAG: Credit card in localStorage
    localStorage.setItem('creditCard', cardNumber);
    localStorage.setItem('cvv', cvv);
    
    const cardData = {
      number: cardNumber,
      cvv: cvv,
      expiry: '12/25',
      holderName: 'John Doe'
    };
    
    // FLAG: Sensitive financial data
    localStorage.setItem('paymentInfo', JSON.stringify(cardData));
    localStorage.setItem('cardDetails', JSON.stringify(cardData));
  }

  // VULNÉRABLE: Base64 n'est pas du chiffrement - DÉTECTÉ
  encodePassword(password: string) {
    // FLAG: Base64 encoding for sensitive data
    const encoded = btoa(password);
    localStorage.setItem('encodedPassword', encoded);
    return encoded;
  }

  // VULNÉRABLE: Logs de données sensibles - DÉTECTÉ
  logSensitiveData() {
    // FLAG: Console.log with sensitive data
    console.log('Password:', localStorage.getItem('userPassword'));
    console.log('Token:', localStorage.getItem('authToken'));
    console.log('API Key:', this.apiKey);
    console.log('Credit Card:', localStorage.getItem('creditCard'));
    console.error('AWS Secret:', this.awsSecretKey);
    
    // FLAG: Logging full user object
    const userData = {
      password: 'user123',
      ssn: '123-45-6789',
      creditCard: '4111111111111111'
    };
    console.log('User Data:', userData);
  }

  // Méthodes pour l'affichage
  getStoredPassword(): string {
    return localStorage.getItem('userPassword') || 'Aucun';
  }

  getStoredToken(): string {
    const token = localStorage.getItem('authToken') || '';
    return token ? token.substring(0, 20) + '...' : 'Aucun';
  }

  exposeSecrets() {
    this.showSecrets = !this.showSecrets;
  }

  // VULNÉRABLE: Cookies sans flags de sécurité - Pattern détecté
  setInsecureCookie(name: string, value: string) {
    // FLAG: Cookie without Secure, HttpOnly, SameSite
    document.cookie = `${name}=${value}`;
    document.cookie = `session=${value}; path=/`;
  }
}