import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';

// Tous les composants vulnérables
import { XssComponent } from './xss/xss.component';
import { StorageComponent } from './storage/storage.component';
import { InjectionComponent } from './injection/injection.component';
import { RedirectComponent } from './redirect/redirect.component';
import { PrototypePollutionComponent } from './prototype-pollution/prototype-pollution.component';
import { PostmessageComponent } from './postmessage/postmessage.component';
import { FileUploadComponent } from './file-upload/file-upload.component';
import { RegexDosComponent } from './regex-dos/regex-dos.component';

@NgModule({
  declarations: [
    AppComponent,
    XssComponent,
    StorageComponent,
    InjectionComponent,
    RedirectComponent,
    PrototypePollutionComponent,
    PostmessageComponent,
    FileUploadComponent,
    RegexDosComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    FormsModule,
    HttpClientModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }