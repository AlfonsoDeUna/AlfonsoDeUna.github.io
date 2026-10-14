// Only this loader is public. The curriculum and application are authenticated ciphertext.
const enc=new TextEncoder(),dec=new TextDecoder();
const un64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
function b64(bytes){let s='';for(let i=0;i<bytes.length;i+=8192)s+=String.fromCharCode(...bytes.subarray(i,i+8192));return btoa(s)}
const STORE='oposiciones-madrid-v1';
document.getElementById('login').addEventListener('submit',async event=>{
  event.preventDefault();const button=document.getElementById('enter'),message=document.getElementById('login-error');
  button.disabled=true;message.textContent='Abriendo tu aula…';
  let payload,key;
  try{
    if(!crypto.subtle)throw new Error('HTTPS_REQUIRED');
    const response=await fetch('./vault.json',{cache:'no-cache'});if(!response.ok)throw new Error('NETWORK');
    const vault=await response.json();
    const user=document.getElementById('username').value.trim().toLowerCase();
    const password=document.getElementById('password').value;
    const material=await crypto.subtle.importKey('raw',enc.encode(user+'\0'+password),'PBKDF2',false,['deriveKey']);
    key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:un64(vault.salt),iterations:vault.iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
    const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:un64(vault.iv),additionalData:enc.encode('oposiciones:app:v1')},key,un64(vault.data));
    payload=JSON.parse(dec.decode(plaintext));
    document.getElementById('password').value='';
  }catch(error){message.textContent=error.message==='HTTPS_REQUIRED'?'Abre la web con HTTPS o desde localhost.':error.message==='NETWORK'?'No se puede cargar el aula. Comprueba tu conexión.':'No se pudo abrir el aula. Revisa usuario, contraseña y conexión.';button.disabled=false;return}
  const seal=async(value,context='progress')=>{const iv=crypto.getRandomValues(new Uint8Array(12));const data=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:enc.encode('oposiciones:'+context+':v1')},key,enc.encode(JSON.stringify(value)));return {version:1,iv:b64(iv),data:b64(new Uint8Array(data))}};
  const open=async(value,context='progress')=>JSON.parse(dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:un64(value.iv),additionalData:enc.encode('oposiciones:'+context+':v1')},key,un64(value.data))));
  let warning='',state=null;
  try{const saved=localStorage.getItem(STORE);if(saved)state=await open(JSON.parse(saved))}catch{warning='No se pudo leer el progreso guardado. Se ha conservado la copia anterior; exporta antes de reemplazarla.'}
  let writeQueue=Promise.resolve(),canWrite=!warning;
  const save=value=>{if(!canWrite)return Promise.reject(new Error('Confirma primero la recuperación del progreso en la guía.'));const snapshot=structuredClone(value);writeQueue=writeQueue.catch(()=>{}).then(async()=>localStorage.setItem(STORE,JSON.stringify(await seal(snapshot))));return writeQueue};
  const style=document.createElement('style');style.textContent=payload.css;document.head.append(style);
  try{
    const url=URL.createObjectURL(new Blob([payload.app],{type:'text/javascript'}));
    const {start}=await import(url);URL.revokeObjectURL(url);
    await start({...payload,state,warning,save,seal,open,allowSave:()=>{canWrite=true},downloadExam:async year=>{
      const r=await fetch('./exams/'+year+'.json');if(!r.ok)throw new Error('No se pudo descargar el PDF.');
      return open(await r.json(),'exam-'+year);
    },logout:async()=>{try{await writeQueue}catch{}location.reload()}});
  }catch(error){document.body.replaceChildren();const p=document.createElement('p');p.textContent='No se pudo iniciar el aula. Recarga la página. '+error.message;document.body.append(p)}
});
