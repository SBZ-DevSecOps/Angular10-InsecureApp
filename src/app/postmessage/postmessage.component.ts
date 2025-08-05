import { Component, OnInit, OnDestroy } from '@angular/core';

@Component({
  selector: 'app-postmessage',
  template: `
    <div class="vulnerability-container">
      <h2>PostMessage Vulnerabilities (Détectable par SAST)</h2>
      
      <div class="demo-section">
        <h3>1. Recevoir Messages Sans Validation</h3>
        <p>Status: {{messageStatus}}</p>
        <p>Dernier message reçu: {{lastMessage}}</p>
        <button (click)="startListening()">Activer Listener</button>
        <button (click)="stopListening()">Désactiver</button>
      </div>

      <div class="demo-section">
        <h3>2. Envoyer Messages avec '*'</h3>
        <input [(ngModel)]="messageToSend" placeholder="Message à envoyer">
        <button (click)="sendToParent()">Send to Parent</button>
        <button (click)="sendToAll()">Broadcast (*)</button>
      </div>

      <div class="demo-section">
        <h3>3. Communication avec iFrame</h3>
        <button (click)="createIframe()">Créer iFrame</button>
        <button (click)="sendToIframe()">Send to iFrame</button>
        <iframe #testFrame id="test-frame" src="about:blank" style="width: 100%; height: 100px; border: 1px solid #ccc;"></iframe>
      </div>

      <div class="demo-section">
        <h3>4. Données Sensibles via PostMessage</h3>
        <button (click)="sendSensitiveData()">Envoyer Token Auth</button>
        <button (click)="sendUserData()">Envoyer Données User</button>
      </div>

      <div class="demo-section">
        <h3>5. Exécution depuis PostMessage</h3>
        <p style="color: red;">⚠️ Simulation - Code non exécuté réellement</p>
        <div id="message-output" style="padding: 10px; background: #f5f5f5; min-height: 50px;"></div>
      </div>
    </div>
  `,
  styles: [`
    .vulnerability-container { padding: 20px; }
    .demo-section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
    input { padding: 5px; margin-right: 10px; width: 300px; }
    button { padding: 5px 15px; cursor: pointer; margin-right: 10px; }
  `]
})
export class PostmessageComponent implements OnInit, OnDestroy {
  messageStatus = 'Listener inactif';
  lastMessage = '';
  messageToSend = 'Hello from vulnerable app!';
  private messageHandler: any;

  ngOnInit() {
    // Auto-start listening (vulnérable)
    this.startListening();
  }

  ngOnDestroy() {
    this.stopListening();
  }

  startListening() {
    // VULNÉRABLE: Event listener sans vérification d'origine - DÉTECTÉ
    this.messageHandler = (event: MessageEvent) => {
      // FLAG: No origin validation
      this.handleMessage(event);
    };
    
    window.addEventListener('message', this.messageHandler);
    this.messageStatus = 'Listener actif (VULNÉRABLE)';
  }

  stopListening() {
    if (this.messageHandler) {
      window.removeEventListener('message', this.messageHandler);
      this.messageStatus = 'Listener inactif';
    }
  }

  // VULNÉRABLE: Pas de vérification d'origine - DÉTECTÉ
  handleMessage(event: MessageEvent) {
    // FLAG: Missing event.origin check
    this.lastMessage = JSON.stringify(event.data);
    
    const data = event.data;
    
    // VULNÉRABLE: Actions basées sur le message - DÉTECTÉ
    if (data.action === 'execute') {
      // FLAG: eval from postMessage (simulé)
      console.log('VULNÉRABLE: eval depuis postMessage:', data.code);
      // eval(data.code); // Commenté pour sécurité
    }
    
    // VULNÉRABLE: innerHTML depuis postMessage - DÉTECTÉ
    if (data.html) {
      const output = document.getElementById('message-output');
      if (output) {
        // FLAG: XSS via postMessage
        output.innerHTML = data.html;
      }
    }
    
    // VULNÉRABLE: Redirection - DÉTECTÉ
    if (data.redirect) {
      // FLAG: Open redirect via postMessage
      console.log('VULNÉRABLE: Redirect vers:', data.redirect);
      // window.location.href = data.redirect; // Commenté
    }
    
    // VULNÉRABLE: Modification du DOM - DÉTECTÉ
    if (data.elementId && data.content) {
      const element = document.getElementById(data.elementId);
      if (element) {
        element.innerHTML = data.content;
      }
    }
  }

  // VULNÉRABLE: postMessage vers * - DÉTECTÉ
  sendToParent() {
    // FLAG: postMessage with wildcard origin
    window.parent.postMessage({
      message: this.messageToSend,
      timestamp: Date.now()
    }, '*');
  }

  // VULNÉRABLE: Broadcast à toutes les fenêtres - DÉTECTÉ
  sendToAll() {
    const data = {
      broadcast: true,
      message: this.messageToSend,
      origin: window.location.origin
    };
    
    // FLAG: postMessage to wildcard
    window.postMessage(data, '*');
    
    // Envoyer au parent aussi
    if (window.parent !== window) {
      window.parent.postMessage(data, '*');
    }
    
    // Envoyer à l'opener si existe
    if (window.opener) {
      window.opener.postMessage(data, '*');
    }
  }

  // VULNÉRABLE: Communication iframe non sécurisée - DÉTECTÉ
  createIframe() {
    const iframe = document.getElementById('test-frame') as HTMLIFrameElement;
    if (iframe) {
      iframe.src = 'https://example.com';
    }
  }

  sendToIframe() {
    const iframe = document.getElementById('test-frame') as HTMLIFrameElement;
    if (iframe && iframe.contentWindow) {
      // FLAG: No origin specified
      iframe.contentWindow.postMessage({
        command: 'getData',
        secret: 'confidential-data'
      }, '*');
    }
  }

  // VULNÉRABLE: Envoi de données sensibles - DÉTECTÉ
  sendSensitiveData() {
    const sensitiveData = {
      // FLAG: Sensitive data in postMessage
      authToken: localStorage.getItem('authToken') || 'fake-token-12345',
      sessionId: sessionStorage.getItem('sessionId') || 'session-67890',
      apiKey: 'sk_live_1234567890'
    };
    
    // FLAG: Broadcasting sensitive data
    window.parent.postMessage(sensitiveData, '*');
  }

  sendUserData() {
    const userData = {
      // FLAG: PII in postMessage
      username: 'john.doe',
      email: 'john@example.com',
      creditCard: '4111111111111111',
      ssn: '123-45-6789',
      password: 'plaintext-password' // TRÈS MAUVAIS
    };
    
    window.postMessage(userData, '*');
  }

  // VULNÉRABLE: Channel messaging sans validation - DÉTECTÉ
  setupMessageChannel() {
    const channel = new MessageChannel();
    
    channel.port1.onmessage = (event) => {
      // FLAG: No validation on MessageChannel
      if (event.data.execute) {
        console.log('VULNÉRABLE: Execute depuis channel:', event.data.execute);
        // eval(event.data.execute); // Commenté
      }
    };
    
    // Envoi du port sans validation
    window.postMessage({ 
      type: 'port',
      port: channel.port2 
    }, '*', [channel.port2]);
  }

  // VULNÉRABLE: BroadcastChannel - Pattern détecté
  setupBroadcastChannel() {
    if ('BroadcastChannel' in window) {
      const channel = new BroadcastChannel('vulnerable_channel');
      
      channel.onmessage = (event) => {
        // FLAG: No validation on BroadcastChannel
        const data = event.data;
        if (data.command) {
          console.log('VULNÉRABLE: Command depuis broadcast:', data.command);
        }
      };
      
      // Envoi sans validation
      channel.postMessage({
        secret: 'broadcast-secret',
        timestamp: Date.now()
      });
    }
  }
}