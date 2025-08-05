import { Component } from '@angular/core';

@Component({
  selector: 'app-injection',
  template: `
    <div class="vulnerability-container">
      <h2>Injection de Code (Détectable par SAST)</h2>
      
      <div class="demo-section">
        <h3>1. eval() Direct</h3>
        <textarea [(ngModel)]="codeInput" placeholder="Ex: alert('Injected!')" rows="3"></textarea>
        <button (click)="executeEval()">Exécuter eval()</button>
        <p>Résultat: {{evalResult}}</p>
      </div>

      <div class="demo-section">
        <h3>2. Function Constructor</h3>
        <input [(ngModel)]="functionCode" placeholder="Ex: return 2 + 2">
        <button (click)="executeFunctionConstructor()">Exécuter Function()</button>
        <p>Résultat: {{functionResult}}</p>
      </div>

      <div class="demo-section">
        <h3>3. setTimeout avec String</h3>
        <input [(ngModel)]="timeoutCode" placeholder="Ex: console.log('Timeout!')">
        <button (click)="executeSetTimeout()">setTimeout(string)</button>
      </div>

      <div class="demo-section">
        <h3>4. JSON.parse avec Fallback eval</h3>
        <textarea [(ngModel)]="jsonInput" placeholder='Ex: {"key": "value"}' rows="3"></textarea>
        <button (click)="parseJsonUnsafe()">Parser JSON</button>
        <p>Résultat: {{jsonResult | json}}</p>
      </div>

      <div class="demo-section">
        <h3>5. Script Injection Dynamique</h3>
        <textarea [(ngModel)]="scriptContent" placeholder="console.log('Script injecté!')" rows="3"></textarea>
        <button (click)="injectScript()">Injecter Script</button>
      </div>

      <div class="demo-section">
        <h3>6. Attribut Event Handler</h3>
        <input [(ngModel)]="eventCode" placeholder="Ex: alert('Click!')">
        <button (click)="setEventHandler()">Créer Bouton</button>
        <div id="dynamic-button-container"></div>
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
    input, textarea {
      padding: 5px;
      margin-right: 10px;
      width: 300px;
    }
    textarea {
      width: 100%;
      margin-bottom: 10px;
    }
    button {
      padding: 5px 15px;
      cursor: pointer;
    }
  `]
})
export class InjectionComponent {
  codeInput = '';
  functionCode = '';
  timeoutCode = '';
  jsonInput = '';
  scriptContent = '';
  eventCode = '';
  
  evalResult: any = '';
  functionResult: any = '';
  jsonResult: any = '';

  // VULNÉRABLE: eval() direct - DÉTECTÉ par tous les SAST
  executeEval() {
    try {
      // FLAG: eval usage
      this.evalResult = eval(this.codeInput);
    } catch (e: any) {
      this.evalResult = 'Erreur: ' + e.message;
    }
  }

  // VULNÉRABLE: Function constructor - DÉTECTÉ
  executeFunctionConstructor() {
    try {
      // FLAG: Function constructor (equivalent to eval)
      const fn = new Function(this.functionCode);
      this.functionResult = fn();
    } catch (e: any) {
      this.functionResult = 'Erreur: ' + e.message;
    }
  }

  // VULNÉRABLE: Function avec return - DÉTECTÉ
  executeFunctionWithReturn() {
    try {
      // FLAG: Function constructor with return
      const fn = new Function('return ' + this.functionCode);
      return fn();
    } catch (e) {
      return null;
    }
  }

  // VULNÉRABLE: setTimeout avec string - DÉTECTÉ
  executeSetTimeout() {
    // FLAG: setTimeout with string (implicit eval)
    setTimeout(this.timeoutCode, 0);
    
    // Alternative aussi vulnérable
    window.setTimeout(this.timeoutCode, 100);
  }

  // VULNÉRABLE: setInterval avec string - DÉTECTÉ
  executeSetInterval() {
    // FLAG: setInterval with string
    const interval = setInterval(this.timeoutCode, 1000);
    
    // Arrêter après 3 secondes
    setTimeout(() => clearInterval(interval), 3000);
  }

  // VULNÉRABLE: JSON.parse avec fallback eval - DÉTECTÉ
  parseJsonUnsafe() {
    try {
      this.jsonResult = JSON.parse(this.jsonInput);
    } catch (e) {
      try {
        // FLAG: eval as JSON.parse fallback
        this.jsonResult = eval('(' + this.jsonInput + ')');
      } catch (e2) {
        this.jsonResult = 'Erreur de parsing';
      }
    }
  }

  // VULNÉRABLE: Script injection - DÉTECTÉ
  injectScript() {
    const script = document.createElement('script');
    // FLAG: Dynamic script text content
    script.textContent = this.scriptContent;
    document.head.appendChild(script);
  }

  // VULNÉRABLE: Element.setAttribute avec event handler - DÉTECTÉ
  setEventHandler() {
    const container = document.getElementById('dynamic-button-container');
    if (container) {
      container.innerHTML = ''; // Clear
      const button = document.createElement('button');
      button.textContent = 'Cliquez-moi!';
      
      // FLAG: Setting onclick attribute with string
      button.setAttribute('onclick', this.eventCode);
      container.appendChild(button);
    }
  }

  // VULNÉRABLE: javascript: protocol - DÉTECTÉ
  executeViaProtocol() {
    // FLAG: javascript: URL
    location.href = 'javascript:' + this.codeInput;
  }

  // VULNÉRABLE: Création de fonction dynamique - DÉTECTÉ
  createDynamicFunction(params: string, body: string): Function {
    // FLAG: Dynamic function creation
    return new Function(params, body);
  }

  // VULNÉRABLE: document.write avec script - DÉTECTÉ
  writeScript() {
    // FLAG: document.write with script
    document.write(`<script>${this.scriptContent}</script>`);
  }
}