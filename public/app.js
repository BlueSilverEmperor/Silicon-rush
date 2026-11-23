/**
 * AXION Web Application Logic
 */

document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const filePreview = document.getElementById('filePreview');
  const fileNameDisplay = document.getElementById('fileName');
  const fileMetaDisplay = document.getElementById('fileMeta');
  const fileBadge = document.getElementById('fileBadge');
  const removeFileBtn = document.getElementById('removeFileBtn');

  const passwordInput = document.getElementById('passwordInput');
  const toggleEyeBtn = document.getElementById('toggleEyeBtn');
  const strengthBar = document.getElementById('strengthBar');
  const strengthText = document.getElementById('strengthText');

  const actionBtn = document.getElementById('actionBtn');
  const demoBtn = document.getElementById('demoBtn');

  const progressContainer = document.getElementById('progressContainer');
  const progressFill = document.getElementById('progressFill');
  const progressPercent = document.getElementById('progressPercent');
  const progressMessage = document.getElementById('progressMessage');

  const resultCard = document.getElementById('resultCard');
  const resultTitle = document.getElementById('resultTitle');
  const resultDesc = document.getElementById('resultDesc');
  const downloadBtn = document.getElementById('downloadBtn');

  const modeTabs = document.querySelectorAll('.mode-tab');
  const formatBtns = document.querySelectorAll('.format-btn');

  const fileArea = document.getElementById('fileArea');
  const textVaultArea = document.getElementById('textVaultArea');
  const vaultInput = document.getElementById('vaultInput');
  const vaultOutput = document.getElementById('vaultOutput');
  const copyVaultBtn = document.getElementById('copyVaultBtn');

  const apiStatus = document.getElementById('apiStatus');

  // State
  let currentMode = 'encrypt'; // 'encrypt' | 'decrypt' | 'vault'
  let currentFormat = 'all'; // 'all' | 'txt' | 'docx' | 'pptx' | 'pdf'
  let selectedFile = null;
  let processedBlobUrl = null;

  // Format mapping
  const formatExtensions = {
    all: ['*'],
    txt: ['.txt', '.md', '.json', '.csv'],
    docx: ['.docx', '.doc'],
    pptx: ['.pptx', '.ppt'],
    pdf: ['.pdf'],
  };

  // Check Serverless API Health
  fetch('/api/health')
    .then(res => res.json())
    .then(data => {
      if (data.status === 'ok') {
        apiStatus.innerHTML = '<span class="pulse-dot"></span> Edge API Ready';
      }
    })
    .catch(() => {
      apiStatus.innerHTML = '<span class="pulse-dot" style="background:#38bdf8"></span> Local WebCrypto Active';
    });

  // Mode Tabs (Encrypt vs Decrypt vs Vault)
  modeTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      modeTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      currentMode = tab.dataset.mode;
      updateUIMode();
    });
  });

  // Format Buttons (All, TXT, DOCX, PPTX, PDF)
  formatBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      formatBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFormat = btn.dataset.format;
      updateFormatFilter();
    });
  });

  function updateFormatFilter() {
    if (currentMode === 'vault') return;
    if (currentFormat === 'all') {
      fileInput.removeAttribute('accept');
    } else {
      fileInput.accept = formatExtensions[currentFormat].join(',');
    }
  }

  function updateUIMode() {
    resetResult();
    if (currentMode === 'vault') {
      fileArea.style.display = 'none';
      textVaultArea.classList.add('visible');
      actionBtn.textContent = 'Process Text in Vault';
    } else {
      fileArea.style.display = 'block';
      textVaultArea.classList.remove('visible');
      if (currentMode === 'encrypt') {
        actionBtn.textContent = 'Encrypt File (.docenc)';
        document.getElementById('dropTitle').textContent = 'Select or drop document to encrypt';
      } else {
        actionBtn.textContent = 'Decrypt File';
        document.getElementById('dropTitle').textContent = 'Select or drop .docenc file to decrypt';
      }
    }
    updateActionBtnState();
  }

  // Drag and Drop
  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.add('drag-active');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.remove('drag-active');
    }, false);
  });

  dropzone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFileSelected(files[0]);
    }
  });

  dropzone.addEventListener('click', () => {
    fileInput.click();
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleFileSelected(e.target.files[0]);
    }
  });

  function handleFileSelected(file) {
    selectedFile = file;
    fileNameDisplay.textContent = file.name;
    fileMetaDisplay.textContent = `${formatBytes(file.size)} • ${file.type || 'Binary'}`;

    const ext = file.name.split('.').pop().toLowerCase();
    fileBadge.textContent = ext || 'FILE';

    dropzone.style.display = 'none';
    filePreview.classList.add('visible');
    resetResult();
    updateActionBtnState();
  }

  removeFileBtn.addEventListener('click', () => {
    clearSelectedFile();
  });

  function clearSelectedFile() {
    selectedFile = null;
    fileInput.value = '';
    dropzone.style.display = 'block';
    filePreview.classList.remove('visible');
    resetResult();
    updateActionBtnState();
  }

  // Password Visibility Toggle
  toggleEyeBtn.addEventListener('click', () => {
    const isPassword = passwordInput.type === 'password';
    passwordInput.type = isPassword ? 'text' : 'password';
    toggleEyeBtn.innerHTML = isPassword 
      ? '<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24M1 1l22 22"/></svg>'
      : '<svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
  });

  // Password Strength Evaluation
  passwordInput.addEventListener('input', () => {
    evaluatePasswordStrength(passwordInput.value);
    updateActionBtnState();
  });

  function evaluatePasswordStrength(password) {
    if (!password) {
      strengthBar.style.width = '0%';
      strengthText.textContent = '';
      return;
    }

    let score = 0;
    if (password.length >= 8) score += 25;
    if (password.length >= 12) score += 15;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 20;
    if (/\d/.test(password)) score += 20;
    if (/[^a-zA-Z0-9]/.test(password)) score += 20;

    strengthBar.style.width = `${score}%`;

    if (score < 40) {
      strengthBar.style.backgroundColor = 'var(--accent-danger)';
      strengthText.textContent = 'Weak Password';
      strengthText.style.color = 'var(--accent-danger)';
    } else if (score < 70) {
      strengthBar.style.backgroundColor = 'var(--accent-warning)';
      strengthText.textContent = 'Moderate Security';
      strengthText.style.color = 'var(--accent-warning)';
    } else {
      strengthBar.style.backgroundColor = 'var(--accent-success)';
      strengthText.textContent = 'High Security (Strong)';
      strengthText.style.color = 'var(--accent-success)';
    }
  }

  function updateActionBtnState() {
    const hasPassword = passwordInput.value.length >= 4;
    if (currentMode === 'vault') {
      actionBtn.disabled = !hasPassword || !vaultInput.value.trim();
    } else {
      actionBtn.disabled = !hasPassword || !selectedFile;
    }
  }

  vaultInput && vaultInput.addEventListener('input', updateActionBtnState);

  // Main Action (Execute Crypto)
  actionBtn.addEventListener('click', async () => {
    const password = passwordInput.value;
    if (password.length < 4) {
      showToast('Password must be at least 4 characters.', 'error');
      return;
    }

    if (currentMode === 'vault') {
      await processTextVault(password);
      return;
    }

    if (!selectedFile) {
      showToast('Please select a file to process.', 'error');
      return;
    }

    await processFile(password);
  });

  async function processFile(password) {
    actionBtn.disabled = true;
    progressContainer.classList.add('active');
    resultCard.classList.remove('visible', 'error');

    updateProgress(15, 'Deriving cryptographic keys (PBKDF2-SHA256 100k)...');

    try {
      const fileBuffer = await readFileAsArrayBuffer(selectedFile);
      const startTime = performance.now();

      updateProgress(45, `${currentMode === 'encrypt' ? 'Encrypting' : 'Decrypting'} binary payload...`);

      let processedBytes;
      let outputFileName;

      if (currentMode === 'encrypt') {
        processedBytes = await AxionCrypto.encrypt(fileBuffer, password);
        outputFileName = selectedFile.name.endsWith('.docenc') 
          ? selectedFile.name + '.enc' 
          : selectedFile.name + '.docenc';
      } else {
        processedBytes = await AxionCrypto.decrypt(fileBuffer, password);
        if (selectedFile.name.endsWith('.docenc')) {
          outputFileName = selectedFile.name.replace(/\.docenc$/i, '');
        } else {
          outputFileName = 'decrypted_' + selectedFile.name;
        }
      }

      updateProgress(90, 'Packaging output file...');

      const durationMs = Math.round(performance.now() - startTime);

      // Create download blob
      if (processedBlobUrl) {
        URL.revokeObjectURL(processedBlobUrl);
      }

      const blob = new Blob([processedBytes], { type: 'application/octet-stream' });
      processedBlobUrl = URL.createObjectURL(blob);

      downloadBtn.href = processedBlobUrl;
      downloadBtn.download = outputFileName;

      updateProgress(100, 'Complete!');

      setTimeout(() => {
        progressContainer.classList.remove('active');
        resultCard.classList.remove('error');
        resultCard.classList.add('visible');
        resultTitle.textContent = currentMode === 'encrypt' ? 'File Encrypted Successfully!' : 'File Decrypted Successfully!';
        resultDesc.textContent = `${outputFileName} (${formatBytes(processedBytes.byteLength)}) generated in ${durationMs}ms.`;
        showToast('Operation completed successfully!', 'success');
        actionBtn.disabled = false;
      }, 300);

    } catch (err) {
      progressContainer.classList.remove('active');
      resultCard.classList.add('visible', 'error');
      resultTitle.textContent = 'Operation Failed';
      resultDesc.textContent = err.message || 'An error occurred during cryptographic processing.';
      downloadBtn.style.display = 'none';
      showToast(err.message, 'error');
      actionBtn.disabled = false;
    }
  }

  async function processTextVault(password) {
    const text = vaultInput.value.trim();
    actionBtn.disabled = true;

    try {
      if (text.startsWith('ey') || /^[A-Za-z0-9+/=]+$/.test(text) && text.length > 40) {
        // Try decrypting first
        try {
          const decrypted = await AxionCrypto.decryptText(text, password);
          vaultOutput.value = decrypted;
          showToast('Text successfully decrypted!', 'success');
          actionBtn.disabled = false;
          return;
        } catch (e) {
          // If fail, fallback to encrypting
        }
      }

      const encrypted = await AxionCrypto.encryptText(text, password);
      vaultOutput.value = encrypted;
      showToast('Text successfully encrypted to Base64!', 'success');
    } catch (err) {
      showToast(err.message || 'Vault operation failed', 'error');
    } finally {
      actionBtn.disabled = false;
    }
  }

  // Copy Vault Result
  copyVaultBtn && copyVaultBtn.addEventListener('click', () => {
    if (vaultOutput.value) {
      navigator.clipboard.writeText(vaultOutput.value);
      showToast('Copied to clipboard!', 'success');
    }
  });

  // Demo Button (Instant Trial)
  demoBtn.addEventListener('click', () => {
    const demoContent = 'AXION Secure Document Locker\nVerified deployment on Vercel with 100% WebCrypto binary compatibility.';
    const blob = new Blob([demoContent], { type: 'text/plain' });
    const demoFile = new File([blob], 'axion_demo_document.txt', { type: 'text/plain' });

    passwordInput.value = 'AxionSecure2026!';
    evaluatePasswordStrength(passwordInput.value);
    handleFileSelected(demoFile);
    showToast('Demo document and password loaded! Click "Encrypt File" to test.', 'success');
  });

  function updateProgress(percent, message) {
    progressFill.style.width = `${percent}%`;
    progressPercent.textContent = `${percent}%`;
    progressMessage.textContent = message;
  }

  function resetResult() {
    resultCard.classList.remove('visible', 'error');
    downloadBtn.style.display = 'inline-flex';
    progressContainer.classList.remove('active');
  }

  function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error);
      reader.readAsArrayBuffer(file);
    });
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.style.borderColor = type === 'error' ? 'var(--accent-danger)' : 'var(--accent-cyan)';
    toast.classList.add('show');
    setTimeout(() => {
      toast.classList.remove('show');
    }, 3500);
  }
});
