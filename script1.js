const loginForm = document.getElementById('loginForm');
const errorElement = document.getElementById('errorMsg');
const loginButton = document.getElementById('loginButton');

loginForm.addEventListener('submit', async event => {
  event.preventDefault();
  errorElement.style.display = 'none';
  loginButton.disabled = true;

  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('username').value.trim(),
        password: document.getElementById('password').value
      })
    });
    const responseText = await response.text();
    let result;
    try {
      result = responseText ? JSON.parse(responseText) : {};
    } catch (_) {
      throw new Error(`Server je vratio neispravan odgovor (HTTP ${response.status}). Proverite da li je API server pokrenut.`);
    }

    if (!response.ok) throw new Error(result.greska || `Prijava nije uspela (HTTP ${response.status}).`);
    if (!responseText) throw new Error('Server je vratio prazan odgovor. Proverite da li je API server pokrenut i da li je povezan sa bazom.');
    if (result.twofaRequired) throw new Error('Ovaj demo nalog zahteva dodatnu potvrdu; koristite nalog bez 2FA ili omogućite potvrdu na stranici.');

    localStorage.setItem('ednevnik-token', result.token);
    localStorage.setItem('ednevnik-user', JSON.stringify(result.korisnik));
    window.location.href = 'html/dashboard.html';
  } catch (error) {
    errorElement.textContent = error.message || 'Došlo je do greške pri prijavi.';
    errorElement.style.display = 'block';
  } finally {
    loginButton.disabled = false;
  }
});
