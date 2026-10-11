document.addEventListener('DOMContentLoaded', () => {
  let sessionNonce = '';
  let verifierOrigin = '';

  const emailInput = document.getElementById('email-input');
  const tokenInput = document.getElementById('token-input');
  const tokenHidden = document.getElementById('token-hidden');
  const sessionNonceEl = document.getElementById('session-nonce-display');
  const verifierOriginEl = document.getElementById('verifier-origin-display');
  const refreshNonceBtn = document.getElementById('btn-refresh-nonce');
  const verifyForm = document.getElementById('email-verify-form');
  const submitBtn = document.getElementById('btn-submit-verify');

  const resultContainer = document.getElementById('result-container');
  const resultBanner = document.getElementById('result-banner');
  const auditList = document.getElementById('audit-list');
  const tokenClaimsBlock = document.getElementById('token-claims-block');

  const otpCard = document.getElementById('otp-card');
  const otpInput = document.getElementById('otp-input');
  const btnSubmitOtp = document.getElementById('btn-submit-otp');
  const otpMessage = document.getElementById('otp-message');

  // Load Session Info
  const tokenStatusBadge = document.getElementById('token-status-badge');

  function updateTokenBadge(length) {
    if (!tokenStatusBadge) return;
    if (length > 0) {
      tokenStatusBadge.style.background = 'rgba(16, 185, 129, 0.2)';
      tokenStatusBadge.style.color = '#34d399';
      tokenStatusBadge.textContent = `✓ トークン取得済 (${length}文字)`;
    } else {
      tokenStatusBadge.style.background = 'rgba(148, 163, 184, 0.15)';
      tokenStatusBadge.style.color = 'var(--text-muted)';
      tokenStatusBadge.textContent = '未取得 (0文字)';
    }
  }

  function setTokenBoth(token) {
    const val = token || '';
    tokenInput.value = val;
    if (tokenHidden) {
      tokenHidden.value = val;
    }
    updateTokenBadge(val.length);
  }

  // Clear previous token when email address is modified by user
  let lastEmailValue = emailInput ? emailInput.value.trim() : '';
  function handleEmailModification() {
    const currentEmail = emailInput ? emailInput.value.trim() : '';
    if (currentEmail !== lastEmailValue) {
      lastEmailValue = currentEmail;
      // Reset previous verification token to prevent mismatch error
      setTokenBoth('');
      if (resultContainer) {
        resultContainer.style.display = 'none';
      }
    }
  }

  if (emailInput) {
    emailInput.addEventListener('input', handleEmailModification);
    emailInput.addEventListener('change', handleEmailModification);
  }

  // Load Session Info
  async function loadSessionInfo() {
    try {
      const res = await fetch('/api/session-info');
      const data = await res.json();
      sessionNonce = data.nonce;
      verifierOrigin = data.verifierOrigin;

      sessionNonceEl.textContent = sessionNonce;
      sessionNonceEl.title = sessionNonce;
      verifierOriginEl.textContent = verifierOrigin;

      // Update origin-trial meta tag if provided by server environment
      if (data.originTrialToken && data.originTrialToken.trim()) {
        let metaEl = document.getElementById('origin-trial-meta');
        if (!metaEl) {
          metaEl = document.createElement('meta');
          metaEl.id = 'origin-trial-meta';
          metaEl.setAttribute('http-equiv', 'origin-trial');
          document.head.prepend(metaEl);
        }
        metaEl.setAttribute('content', data.originTrialToken.trim());
      }

      // Bind nonce to the official hidden input as specified in Chrome Email Verification spec
      if (tokenHidden) {
        tokenHidden.setAttribute('nonce', sessionNonce);
      }
      tokenInput.setAttribute('nonce', sessionNonce);
    } catch (err) {
      console.error('Failed to load session info:', err);
      sessionNonceEl.textContent = 'エラー';
    }
  }

  // Listen to standard FormData event in case Chrome injects via form pipeline
  verifyForm.addEventListener('formdata', (e) => {
    const tokenFromFd = e.formData.get('token');
    if (tokenFromFd && typeof tokenFromFd === 'string' && tokenFromFd.trim()) {
      tokenInput.value = tokenFromFd.trim();
      if (tokenHidden) tokenHidden.value = tokenFromFd.trim();
      updateTokenBadge(tokenFromFd.trim().length);
    }
  });

  // Monitor Chrome autofill in tokenHidden and sync to tokenInput textarea
  if (tokenHidden) {
    const onTokenChange = () => {
      const val = tokenHidden.value ? tokenHidden.value.trim() : '';
      if (val && tokenInput.value !== val) {
        tokenInput.value = val;
      }
      updateTokenBadge(val.length);
    };

    tokenHidden.addEventListener('input', onTokenChange);
    tokenHidden.addEventListener('change', onTokenChange);

    // Periodic poll in case Chrome sets DOM property without dispatching events
    setInterval(() => {
      const currentVal = tokenHidden.value ? tokenHidden.value.trim() : (tokenInput.value ? tokenInput.value.trim() : '');
      if (tokenHidden.value && tokenInput.value !== tokenHidden.value) {
        tokenInput.value = tokenHidden.value;
      }
      updateTokenBadge(currentVal.length);
    }, 200);
  }

  // Refresh Nonce
  refreshNonceBtn.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/session-info/refresh', { method: 'POST' });
      const data = await res.json();
      sessionNonce = data.nonce;
      sessionNonceEl.textContent = sessionNonce;
      if (tokenHidden) {
        tokenHidden.setAttribute('nonce', sessionNonce);
      }
      tokenInput.setAttribute('nonce', sessionNonce);
    } catch (err) {
      console.error('Failed to refresh nonce:', err);
    }
  });

  function resolveCurrentToken() {
    if (tokenHidden && tokenHidden.value && tokenHidden.value.trim()) {
      return tokenHidden.value.trim();
    }
    if (tokenInput && tokenInput.value && tokenInput.value.trim()) {
      return tokenInput.value.trim();
    }
    const fd = new FormData(verifyForm);
    const fdToken = fd.get('token');
    if (fdToken && typeof fdToken === 'string' && fdToken.trim()) {
      return fdToken.trim();
    }
    return '';
  }

  // Verify Form Submit
  verifyForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const email = emailInput.value.trim();
    if (!email) {
      alert('メールアドレスを入力してください。');
      return;
    }

    submitBtn.disabled = true;

    // Check if Chrome is still in the middle of issuance after popup confirmation
    let token = resolveCurrentToken();
    if (!token) {
      submitBtn.textContent = 'Chrome トークン受信待機中...';
      // Wait up to 1.8s for Chrome background issuance to complete
      for (let i = 0; i < 6; i++) {
        await new Promise(r => setTimeout(r, 300));
        token = resolveCurrentToken();
        if (token) {
          console.log(`[EVP Submit] Token captured after wait (${(i + 1) * 300}ms):`, token.length, 'chars');
          break;
        }
      }
    }

    console.log('[EVP Submit] Email:', email, 'Final token length:', token.length);
    submitBtn.textContent = '暗号検証中...';

    try {
      const res = await fetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, token })
      });
      const data = await res.json();
      renderResult(data, email);
    } catch (err) {
      console.error('Verification request failed:', err);
      alert('検証リクエストの送信中にエラーが発生しました。');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'メールアドレスを確認する';
    }
  });

  // Render Verification Results
  function renderResult(result, email) {
    resultContainer.style.display = 'block';
    auditList.innerHTML = '';
    otpCard.style.display = 'none';

    // Banner styling
    resultBanner.className = 'result-banner';
    if (result.success) {
      resultBanner.classList.add('success');
      resultBanner.innerHTML = `
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        <div>
          <h4>暗号署名検証 成功</h4>
          <p>Chrome メール確認プロトコル (RFC 9901 SD-JWT+KB) により <strong>${result.verifiedEmail}</strong> の所有が証明されました。</p>
        </div>
      `;
    } else if (result.fallbackRequired) {
      resultBanner.classList.add('fallback');
      resultBanner.innerHTML = `
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        <div>
          <h4>フォールバック要求 (OTP送信)</h4>
          <p>${result.message}</p>
        </div>
      `;
      // Show OTP fallback form
      otpCard.style.display = 'block';
    } else {
      resultBanner.classList.add('failure');
      resultBanner.innerHTML = `
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
        <div>
          <h4>検証失敗</h4>
          <p>${result.message}</p>
        </div>
      `;
    }

    // Render Audit Steps
    if (result.auditLog && result.auditLog.length > 0) {
      result.auditLog.forEach(step => {
        const li = document.createElement('li');
        li.className = `audit-item ${step.passed ? 'passed' : 'failed'}`;
        li.innerHTML = `
          <div class="audit-icon ${step.passed ? 'passed' : 'failed'}">
            ${step.passed
              ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>'
              : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>'}
          </div>
          <div class="audit-content">
            <div class="audit-header">
              <span>${step.title}</span>
              <span class="audit-step-no">Step ${step.stepNumber}</span>
            </div>
            <div class="audit-details">${escapeHtml(step.details)}</div>
          </div>
        `;
        auditList.appendChild(li);
      });
    }

    // Render Token Claims
    if (result.tokenClaims && Object.keys(result.tokenClaims).length > 0) {
      tokenClaimsBlock.textContent = JSON.stringify(result.tokenClaims, null, 2);
    } else {
      tokenClaimsBlock.textContent = '(トークンクレームなし)';
    }

    // Scroll smoothly to result
    resultContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // Handle OTP Submission
  btnSubmitOtp.addEventListener('click', async () => {
    const email = emailInput.value.trim();
    const otpCode = otpInput.value.trim();
    if (!otpCode) {
      alert('確認コードを入力してください。');
      return;
    }

    try {
      const res = await fetch('/api/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otpCode })
      });
      const data = await res.json();
      if (data.success) {
        otpMessage.style.color = '#34d399';
        otpMessage.textContent = '✓ ' + data.message;
        otpCard.style.borderColor = 'rgba(16, 185, 129, 0.4)';
      } else {
        otpMessage.style.color = '#fb7185';
        otpMessage.textContent = '✗ ' + data.message;
      }
    } catch (err) {
      console.error('OTP verify failed:', err);
    }
  });

  // Direct Token Fill Button
  const btnFillToken = document.getElementById('btn-fill-token');
  if (btnFillToken) {
    btnFillToken.addEventListener('click', async () => {
      const email = emailInput.value.trim() || 'demo@example.com';
      emailInput.value = email;
      btnFillToken.disabled = true;
      btnFillToken.textContent = '生成中...';
      try {
        const res = await fetch('/api/issuer/generate-sample-token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: email,
            nonce: sessionNonce,
            aud: verifierOrigin,
            includeKid: false
          })
        });
        const data = await res.json();
        setTokenBoth(data.token);
        btnFillToken.textContent = '✓ セット完了';
        setTimeout(() => {
          btnFillToken.disabled = false;
          btnFillToken.textContent = '⚡ トークン生成・セット';
        }, 1500);
      } catch (err) {
        alert('トークン生成に失敗しました: ' + err.message);
        btnFillToken.disabled = false;
        btnFillToken.textContent = '⚡ トークン生成・セット';
      }
    });
  }

  // Simulator Buttons
  document.getElementById('btn-sim-nokid').addEventListener('click', async () => {
    emailInput.value = 'user@example.com';
    try {
      const res = await fetch('/api/issuer/generate-sample-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'user@example.com',
          nonce: sessionNonce,
          aud: verifierOrigin,
          includeKid: false // Chrome Oct 2026 update: kid omitted, loop through keys!
        })
      });
      const data = await res.json();
      setTokenBoth(data.token);
      verifyForm.requestSubmit();
    } catch (err) {
      alert('トークン生成失敗: ' + err.message);
    }
  });

  document.getElementById('btn-sim-kid').addEventListener('click', async () => {
    emailInput.value = 'user@example.com';
    try {
      const res = await fetch('/api/issuer/generate-sample-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'user@example.com',
          nonce: sessionNonce,
          aud: verifierOrigin,
          includeKid: true
        })
      });
      const data = await res.json();
      setTokenBoth(data.token);
      verifyForm.requestSubmit();
    } catch (err) {
      alert('トークン生成失敗: ' + err.message);
    }
  });

  document.getElementById('btn-sim-fallback').addEventListener('click', () => {
    emailInput.value = 'fallback.user@example.com';
    setTokenBoth(''); // empty triggers fallback
    verifyForm.requestSubmit();
  });

  document.getElementById('btn-sim-tamper').addEventListener('click', async () => {
    emailInput.value = 'user@example.com';
    try {
      const res = await fetch('/api/issuer/generate-sample-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'user@example.com',
          nonce: sessionNonce,
          aud: verifierOrigin,
          includeKid: true
        })
      });
      const data = await res.json();
      // Corrupt a few characters in EVT payload
      const parts = data.token.split('~');
      const tampered = parts[0].substring(0, parts[0].length - 6) + "XXXXXX" + "~" + parts[1];
      setTokenBoth(tampered);
      verifyForm.requestSubmit();
    } catch (err) {
      alert('エラー: ' + err.message);
    }
  });

  // Tabs Handling
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const target = btn.getAttribute('data-tab');
      document.getElementById(target).classList.add('active');
    });
  });

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#039;');
  }

  // Initialize
  loadSessionInfo();
});
