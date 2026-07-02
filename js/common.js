/* ============================================================
   KARTHIK×CORE — shared client helpers
   ============================================================ */

function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function showToast(msg){
  let t = document.getElementById('toast');
  if(!t){
    t = document.createElement('div');
    t.id = 'toast';
    t.className = 'toast';
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => t.classList.remove('show'), 2400);
}

/**
 * Guards a page that requires a verified access key.
 * Redirects to index.html if no valid key is present.
 * Returns the verified key on success.
 */
async function requireAccessKey(){
  const key = localStorage.getItem('core_key');
  if(!key){
    window.location.href = 'index.html';
    return null;
  }
  try{
    const res = await fetch('/api/verify-key', {
      method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({key})
    });
    const data = await res.json();
    if(!data.valid){
      localStorage.removeItem('core_key');
      window.location.href = 'index.html';
      return null;
    }
    return key;
  }catch(e){
    // network hiccup — don't lock the user out, let the page render;
    // it will fail gracefully on the next API call instead.
    return key;
  }
}

function signOut(){
  localStorage.removeItem('core_key');
  window.location.href = 'index.html';
}

function markActiveNav(){
  const path = window.location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.app-nav a').forEach(a => {
    if(a.getAttribute('href') === path) a.classList.add('active');
  });
}

function wireSignOut(){
  const btn = document.getElementById('signOutBtn');
  if(btn) btn.addEventListener('click', signOut);
}

