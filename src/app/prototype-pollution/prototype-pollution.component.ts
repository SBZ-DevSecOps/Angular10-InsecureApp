import { Component } from '@angular/core';

// Déclarations globales
declare const _: any;
declare const $: any;

@Component({
  selector: 'app-prototype-pollution',
  template: `
    <div class="vulnerability-container">
      <h2>Prototype Pollution (Détectable par SAST)</h2>
      
      <div class="demo-section">
        <h3>1. Merge Récursif Sans Protection</h3>
        <textarea [(ngModel)]="jsonInput" placeholder='{"__proto__": {"isAdmin": true}}' rows="4"></textarea>
        <button (click)="testDeepMerge()">Test Deep Merge</button>
        <p>Résultat: {{mergeResult | json}}</p>
        <button (click)="checkPollution()">Vérifier Pollution</button>
        <p *ngIf="pollutionCheck">{{pollutionCheck}}</p>
      </div>

      <div class="demo-section">
        <h3>2. Object.assign avec Entrée Utilisateur</h3>
        <input [(ngModel)]="assignInput" placeholder='{"constructor": {"prototype": {"polluted": true}}}'>
        <button (click)="testObjectAssign()">Test Object.assign</button>
      </div>

      <div class="demo-section">
        <h3>3. Spread Operator Non Sécurisé</h3>
        <input [(ngModel)]="spreadInput" placeholder='{"__proto__": {"vulnerable": true}}'>
        <button (click)="testSpreadOperator()">Test Spread</button>
      </div>

      <div class="demo-section">
        <h3>4. Set Nested Property</h3>
        <input [(ngModel)]="propertyPath" placeholder="__proto__.isAdmin">
        <input [(ngModel)]="propertyValue" placeholder="true">
        <button (click)="testSetProperty()">Set Property</button>
      </div>

      <div class="demo-section">
        <h3>5. Parse Query String Vulnérable</h3>
        <input [(ngModel)]="queryString" placeholder="__proto__[polluted]=yes&user=admin">
        <button (click)="testParseQuery()">Parse Query</button>
        <p>Résultat: {{queryResult | json}}</p>
      </div>
    </div>
  `,
  styles: [`
    .vulnerability-container { padding: 20px; }
    .demo-section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
    input, textarea { padding: 5px; margin-right: 10px; width: 100%; margin-bottom: 10px; }
    button { padding: 5px 15px; cursor: pointer; margin-right: 10px; }
  `]
})
export class PrototypePollutionComponent {
  jsonInput = '';
  assignInput = '';
  spreadInput = '';
  propertyPath = '';
  propertyValue = '';
  queryString = '';
  
  mergeResult: any = {};
  queryResult: any = {};
  pollutionCheck = '';

  // VULNÉRABLE: Deep merge sans protection - DÉTECTÉ
  deepMerge(target: any, source: any): any {
    for (const key in source) {
      // FLAG: No prototype pollution protection
      if (source[key] && typeof source[key] === 'object') {
        target[key] = target[key] || {};
        this.deepMerge(target[key], source[key]);
      } else {
        target[key] = source[key]; // Permet __proto__ pollution
      }
    }
    return target;
  }

  testDeepMerge() {
    try {
      const source = JSON.parse(this.jsonInput);
      this.mergeResult = {};
      this.deepMerge(this.mergeResult, source);
    } catch (e) {
      this.mergeResult = { error: 'JSON invalide' };
    }
  }

  // VULNÉRABLE: Object.assign - DÉTECTÉ
  testObjectAssign() {
    try {
      const source = JSON.parse(this.assignInput);
      const target = {};
      
      // FLAG: Object.assign with user input
      Object.assign(target, source);
      
      // Test aussi avec multiple sources
      const result = Object.assign({}, target, source);
    } catch (e) {
      console.error('Erreur:', e);
    }
  }

  // VULNÉRABLE: Spread operator - DÉTECTÉ
  testSpreadOperator() {
    try {
      const source = JSON.parse(this.spreadInput);
      
      // FLAG: Spread with user input
      const merged = {...source};
      const merged2 = {...{}, ...source};
      
      // Aussi vulnérable
      const arr = [...[source]];
    } catch (e) {
      console.error('Erreur:', e);
    }
  }

  // VULNÉRABLE: Set nested property - DÉTECTÉ
  setNestedProperty(obj: any, path: string, value: any): void {
    const keys = path.split('.');
    let current = obj;
    
    for (let i = 0; i < keys.length - 1; i++) {
      // FLAG: Dynamic property access without validation
      if (!current[keys[i]]) {
        current[keys[i]] = {};
      }
      current = current[keys[i]];
    }
    
    // Permet de set __proto__ ou constructor
    current[keys[keys.length - 1]] = value;
  }

  testSetProperty() {
    const obj = {};
    this.setNestedProperty(obj, this.propertyPath, this.propertyValue);
    console.log('Property set:', obj);
  }

  // VULNÉRABLE: Parse query string - DÉTECTÉ
  parseQueryString(query: string): any {
    const params: any = {};
    const pairs = query.split('&');
    
    for (const pair of pairs) {
      const [key, value] = pair.split('=');
      // FLAG: Setting nested properties from user input
      this.setNestedProperty(params, decodeURIComponent(key), decodeURIComponent(value || ''));
    }
    
    return params;
  }

  testParseQuery() {
    this.queryResult = this.parseQueryString(this.queryString);
  }

  // VULNÉRABLE: Clone sans protection - DÉTECTÉ
  unsafeClone(obj: any): any {
    if (obj === null || typeof obj !== 'object') return obj;
    
    const cloned: any = {};
    for (const key in obj) {
      // FLAG: Cloning without prototype check
      cloned[key] = this.unsafeClone(obj[key]);
    }
    return cloned;
  }

  // VULNÉRABLE: Lodash/jQuery si présent - DÉTECTÉ
  testLibraryPollution() {
    // Lodash vulnerable
    if (typeof _ !== 'undefined') {
      const malicious = JSON.parse('{"__proto__": {"polluted": true}}');
      _.merge({}, malicious);
      _.defaultsDeep({}, malicious);
    }
    
    // jQuery vulnerable
    if (typeof $ !== 'undefined') {
      const malicious = JSON.parse('{"__proto__": {"polluted": true}}');
      $.extend(true, {}, malicious);
    }
  }

  checkPollution() {
    const testObj: any = {};
    this.pollutionCheck = `
      Object vide - isAdmin: ${testObj.isAdmin}
      Object vide - polluted: ${testObj.polluted}
      Object vide - vulnerable: ${testObj.vulnerable}
    `;
  }
}