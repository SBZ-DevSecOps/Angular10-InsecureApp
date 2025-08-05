import { Component } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

@Component({
  selector: 'app-file-upload',
  template: `
    <div class="vulnerability-container">
      <h2>File Upload Vulnerabilities (Détectable par SAST)</h2>
      
      <div class="demo-section">
        <h3>1. Upload Sans Validation</h3>
        <input type="file" 
               #fileInput
               (change)="onFileSelected($event)"
               accept="*/*">
        <p>Fichier: {{selectedFileName}}</p>
        <div id="file-name-display"></div>
      </div>

      <div class="demo-section">
        <h3>2. Multiple Files Sans Limite</h3>
        <input type="file" 
               multiple
               (change)="onMultipleFiles($event)">
        <p>Nombre de fichiers: {{fileCount}}</p>
      </div>

      <div class="demo-section">
        <h3>3. Preview d'Image Non Sécurisée</h3>
        <input type="file" 
               accept="image/*"
               (change)="previewImage($event)">
        <div *ngIf="imagePreview">
          <img [src]="imagePreview" style="max-width: 300px;">
          <div [innerHTML]="svgContent"></div>
        </div>
      </div>

      <div class="demo-section">
        <h3>4. Nom de Fichier dans innerHTML</h3>
        <div [innerHTML]="fileNameHtml"></div>
        <div id="filename-output"></div>
      </div>

      <div class="demo-section">
        <h3>5. FileReader Sans Limite</h3>
        <input type="file" (change)="readLargeFile($event)">
        <p>Status: {{readStatus}}</p>
      </div>

      <div class="demo-section">
        <h3>6. Exécution Basée sur Extension</h3>
        <input type="file" (change)="handleByExtension($event)">
        <p>Type détecté: {{detectedType}}</p>
      </div>
    </div>
  `,
  styles: [`
    .vulnerability-container { padding: 20px; }
    .demo-section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
    input[type="file"] { margin-bottom: 10px; }
    img { border: 1px solid #ddd; margin-top: 10px; }
  `]
})
export class FileUploadComponent {
  selectedFileName = '';
  fileCount = 0;
  imagePreview: any = '';
  svgContent: any = '';
  fileNameHtml = '';
  readStatus = '';
  detectedType = '';

  constructor(private sanitizer: DomSanitizer) {}

  // VULNÉRABLE: Pas de validation - DÉTECTÉ
  onFileSelected(event: any) {
    const file = event.target.files[0];
    if (!file) return;
    
    // FLAG: No file type validation
    // FLAG: No file size validation
    // FLAG: No file extension validation
    
    this.selectedFileName = file.name;
    
    // VULNÉRABLE: XSS via nom de fichier - DÉTECTÉ
    this.displayFileName(file);
    
    // Process sans validation
    this.processFile(file);
  }

  // VULNÉRABLE: Pas de limite - DÉTECTÉ
  onMultipleFiles(event: any) {
    const files = event.target.files;
    
    // FLAG: No limit on file count
    this.fileCount = files.length;
    
    // FLAG: No total size validation
    for (let i = 0; i < files.length; i++) {
      this.processFile(files[i]);
    }
  }

  // VULNÉRABLE: Process sans validation - DÉTECTÉ
  processFile(file: File) {
    // FLAG: No validation before processing
    console.log('Processing:', file.name, 'Type:', file.type, 'Size:', file.size);
    
    // Trust du MIME type
    if (file.type) {
      // FLAG: Trusting user-provided MIME type
      console.log('MIME type:', file.type);
    }
  }

  // VULNÉRABLE: XSS via nom de fichier - DÉTECTÉ
  displayFileName(file: File) {
    // FLAG: File name in innerHTML
    this.fileNameHtml = `Fichier uploadé: <strong>${file.name}</strong>`;
    
    // FLAG: Direct DOM manipulation with file name
    const element = document.getElementById('filename-output');
    if (element) {
      element.innerHTML = `<p>Nom du fichier: ${file.name}</p>`;
    }
    
    // Double vulnérabilité
    const fileNameDisplay = document.getElementById('file-name-display');
    if (fileNameDisplay) {
      fileNameDisplay.innerHTML = file.name;
    }
  }

  // VULNÉRABLE: Preview sans validation - DÉTECTÉ
  previewImage(event: any) {
    const file = event.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    
    reader.onload = (e: any) => {
      // FLAG: No validation before preview
      if (file.type.startsWith('image/')) {
        // VULNÉRABLE: SVG peut contenir du JS - DÉTECTÉ
        if (file.type === 'image/svg+xml') {
          // FLAG: SVG preview without sanitization
          this.svgContent = this.sanitizer.bypassSecurityTrustHtml(e.target.result);
        } else {
          // FLAG: Direct image src assignment
          this.imagePreview = this.sanitizer.bypassSecurityTrustUrl(e.target.result);
        }
      }
      
      // VULNÉRABLE: HTML preview - DÉTECTÉ
      if (file.type === 'text/html') {
        // FLAG: HTML file preview
        const output = document.getElementById('filename-output');
        if (output) {
          output.innerHTML = e.target.result;
        }
      }
    };
    
    // FLAG: Reading file without validation
    reader.readAsDataURL(file);
  }

  // VULNÉRABLE: FileReader sans limite - DÉTECTÉ
  readLargeFile(event: any) {
    const file = event.target.files[0];
    if (!file) return;
    
    // FLAG: No size limit before reading
    this.readStatus = 'Lecture en cours...';
    
    const reader = new FileReader();
    reader.onload = () => {
      this.readStatus = `Lu ${file.size} octets`;
    };
    
    // Peut causer OOM avec gros fichiers
    reader.readAsArrayBuffer(file);
  }

  // VULNÉRABLE: Exécution basée sur extension - DÉTECTÉ
  handleByExtension(event: any) {
    const file = event.target.files[0];
    if (!file) return;
    
    const extension = file.name.split('.').pop()?.toLowerCase();
    this.detectedType = extension || 'unknown';
    
    // FLAG: Action based on file extension
    if (extension === 'js') {
      // FLAG: Attempting to execute JS file
      const reader = new FileReader();
      reader.onload = (e) => {
        console.log('VULNÉRABLE: Contenu JS:', e.target?.result);
        // eval(e.target?.result as string); // Commenté
      };
      reader.readAsText(file);
    }
    
    if (extension === 'json') {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          // FLAG: Parsing untrusted JSON
          const data = JSON.parse(e.target?.result as string);
          console.log('JSON parsed:', data);
        } catch {
          // FLAG: eval fallback
          // eval('window.uploadedData = ' + e.target?.result);
        }
      };
      reader.readAsText(file);
    }
  }

  // VULNÉRABLE: Nom non sanitisé - DÉTECTÉ
  sanitizeFileName(fileName: string): string {
    // FLAG: Insufficient sanitization
    return fileName.replace(' ', '_'); // Ne supprime pas ../ ou caractères dangereux
  }

  // VULNÉRABLE: Upload vers URL dynamique - DÉTECTÉ
  uploadToUrl(file: File, url: string) {
    // FLAG: Unvalidated upload destination
    const formData = new FormData();
    formData.append('file', file);
    
    // fetch(url, { method: 'POST', body: formData });
  }

  // VULNÉRABLE: Trust du contenu - DÉTECTÉ
  trustFileContent(file: File) {
    if (file.name.endsWith('.html')) {
      const reader = new FileReader();
      reader.onload = (e) => {
        // FLAG: Trusting HTML content
        document.body.innerHTML += e.target?.result;
      };
      reader.readAsText(file);
    }
  }
}