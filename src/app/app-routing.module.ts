import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

// Import de tous les composants
import { XssComponent } from './xss/xss.component';
import { StorageComponent } from './storage/storage.component';
import { InjectionComponent } from './injection/injection.component';
import { RedirectComponent } from './redirect/redirect.component';
import { PrototypePollutionComponent } from './prototype-pollution/prototype-pollution.component';
import { PostmessageComponent } from './postmessage/postmessage.component';
import { FileUploadComponent } from './file-upload/file-upload.component';
import { RegexDosComponent } from './regex-dos/regex-dos.component';

const routes: Routes = [
  { path: '', redirectTo: '/xss', pathMatch: 'full' },
  { path: 'xss', component: XssComponent },
  { path: 'storage', component: StorageComponent },
  { path: 'injection', component: InjectionComponent },
  { path: 'redirect', component: RedirectComponent },
  { path: 'prototype-pollution', component: PrototypePollutionComponent },
  { path: 'postmessage', component: PostmessageComponent },
  { path: 'file-upload', component: FileUploadComponent },
  { path: 'regex-dos', component: RegexDosComponent },
  { path: '**', redirectTo: '/xss' }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }