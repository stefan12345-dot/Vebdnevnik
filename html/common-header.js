(() => {
  const KEY = 'ednevnik-demo';
  let data = {};
  try { data = JSON.parse(localStorage.getItem(KEY)) || {}; } catch (_) {}

  const header = document.querySelector('.app-header');
  const selectors = document.querySelector('.app-selectors');
  if (!header || !selectors) return;

  const nav = document.querySelector('.app-nav');
  if (nav) {
    const notice = document.createElement('aside');
    notice.className = 'independent-demo-notice';
    notice.setAttribute('role', 'note');
    notice.textContent = 'Nezavisna demonstracija — nije zvanični portal. Podaci su primeri; ne unosite stvarne podatke učenika.';
    nav.insertAdjacentElement('afterend', notice);
  }

  const fill = (id, label, values, remembered = '') => {
    const select = document.getElementById(id);
    if (!select) return;
    select.replaceChildren(new Option(label, ''));
    [...new Set(values.filter(Boolean))].forEach(value => select.add(new Option(value, value)));
    if (remembered && [...select.options].some(option => option.value === remembered)) select.value = remembered;
  };

  const schoolValues = (data.schools || []).map(item => typeof item === 'string' ? item : item.name).filter(Boolean);
  fill('headerSchool', 'Izaberi školu', schoolValues.length ? schoolValues : ['Osnovna škola'], localStorage.getItem('ednevnik-school') || '');
  fill('headerYear', 'Izaberi školsku godinu', ['2024/2025'], localStorage.getItem('ednevnik-year') || '');
  fill('headerClass', 'Izaberi odeljenje', data.classes?.length ? data.classes : ['VIII-2'], localStorage.getItem('ednevnik-class') || '');
  fill('headerSubject', 'Izaberi predmet', data.subjects?.length ? data.subjects : ['Srpski jezik','Matematika','Biologija','Istorija','Engleski jezik','Fizika','Hemija','Geografija'], localStorage.getItem('ednevnik-subject') || '');

  const mobileToggle = document.createElement('button');
  mobileToggle.type = 'button';
  mobileToggle.className = 'header-toggle';
  mobileToggle.setAttribute('aria-expanded', 'false');
  mobileToggle.setAttribute('aria-label', 'Prikaži izbor škole, godine, odeljenja i predmeta');
  mobileToggle.innerHTML = '<span>Izbori</span><span class="toggle-arrow" aria-hidden="true">▾</span>';
  selectors.id = selectors.id || 'headerSelectors';
  mobileToggle.setAttribute('aria-controls', selectors.id);
  header.insertBefore(mobileToggle, selectors);
  mobileToggle.addEventListener('click', () => {
    const open = header.classList.toggle('selectors-open');
    mobileToggle.setAttribute('aria-expanded', String(open));
  });

  const profile = document.createElement('div');
  profile.className = 'profile-menu';
  let user = {};
  try { user = JSON.parse(localStorage.getItem('ednevnik-user')) || {}; } catch (_) {}
  const name = user.ime || user.name || user.korisnicko_ime || user.username || 'Moj profil';
  const initials = name.split(/\s+/).slice(0, 2).map(part => part[0]).join('').toLocaleUpperCase('sr');
  profile.innerHTML = '<button class="profile-trigger" type="button" aria-expanded="false"><span class="profile-avatar"></span><span class="profile-name"></span><span aria-hidden="true">▾</span></button><div class="profile-dropdown" hidden><a href="uredi.profil.html">Uredi profil</a><button type="button" class="logout-button">Odjavi se</button></div>';
  profile.querySelector('.profile-avatar').textContent = initials || 'JA';
  profile.querySelector('.profile-name').textContent = name;
  header.appendChild(profile);
  const profileTrigger = profile.querySelector('.profile-trigger');
  profileTrigger.addEventListener('click', () => {
    const menu = profile.querySelector('.profile-dropdown');
    menu.hidden = !menu.hidden;
    profileTrigger.setAttribute('aria-expanded', String(!menu.hidden));
  });
  profile.querySelector('.logout-button').addEventListener('click', () => {
    localStorage.removeItem('ednevnik-user');
    localStorage.removeItem('ednevnik-token');
    location.href = '../index.html';
  });

  [['headerSchool','ednevnik-school'],['headerYear','ednevnik-year'],['headerClass','ednevnik-class'],['headerSubject','ednevnik-subject']].forEach(([id, key]) => {
    document.getElementById(id)?.addEventListener('change', event => {
      localStorage.setItem(key, event.target.value);
      if (id === 'headerSubject') document.dispatchEvent(new CustomEvent('ednevnik:subject-change', { detail: event.target.value }));
    });
  });
})();
