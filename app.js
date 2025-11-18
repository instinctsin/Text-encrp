const METHOD_CONFIGS = {
  V1: {
    label: 'V1 · AES-GCM',
    algorithm: 'AES-GCM',
    ivLength: 12,
    iterations: 250000,
    extra: { tagLength: 128 },
  },
  V2: {
    label: 'V2 · AES-CBC',
    algorithm: 'AES-CBC',
    ivLength: 16,
    iterations: 200000,
  },
  V3: {
    label: 'V3 · AES-CTR',
    algorithm: 'AES-CTR',
    ivLength: 16,
    iterations: 150000,
    extra: { length: 64 },
  },
};

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const encryptForm = document.getElementById('encrypt-form');
const decryptForm = document.getElementById('decrypt-form');
const encryptResult = document.getElementById('encrypt-result');
const encryptOutput = document.getElementById('encrypted-output');
const copyButton = document.getElementById('copy-encrypted');
const decryptResults = document.getElementById('decrypt-results');
const decryptTemplate = document.getElementById('decrypt-card');

function bufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    buffer[i] = binary.charCodeAt(i);
  }
  return buffer.buffer;
}

function getRandomBytes(length) {
  return window.crypto.getRandomValues(new Uint8Array(length));
}

async function getKeyMaterial(passphrase) {
  const keyData = textEncoder.encode(passphrase);
  return window.crypto.subtle.importKey('raw', keyData, 'PBKDF2', false, [
    'deriveKey',
  ]);
}

function getAlgorithmParams(config, iv) {
  if (config.algorithm === 'AES-GCM') {
    return { name: 'AES-GCM', iv, tagLength: config.extra?.tagLength ?? 128 };
  }

  if (config.algorithm === 'AES-CTR') {
    return { name: 'AES-CTR', counter: iv, length: config.extra?.length ?? 64 };
  }

  return { name: 'AES-CBC', iv };
}

async function deriveAesKey(keyMaterial, salt, config) {
  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: config.iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: config.algorithm, length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptText({ version, plainText, passphrase }) {
  const config = METHOD_CONFIGS[version];
  const keyMaterial = await getKeyMaterial(passphrase);
  const salt = getRandomBytes(16);
  const iv = getRandomBytes(config.ivLength);
  const key = await deriveAesKey(keyMaterial, salt, config);
  const encoded = textEncoder.encode(plainText);
  const algorithmParams = getAlgorithmParams(config, iv);
  const cipherBuffer = await window.crypto.subtle.encrypt(
    algorithmParams,
    key,
    encoded
  );

  return {
    version,
    algorithm: config.label,
    iterations: config.iterations,
    salt: bufferToBase64(salt),
    iv: bufferToBase64(iv),
    ciphertext: bufferToBase64(cipherBuffer),
  };
}

async function decryptWithVersion({ version, payload, passphrase }) {
  const config = METHOD_CONFIGS[version];
  try {
    const keyMaterial = await getKeyMaterial(passphrase);
    const salt = base64ToArrayBuffer(payload.salt);
    const iv = base64ToArrayBuffer(payload.iv);
    const key = await deriveAesKey(keyMaterial, salt, config);
    const algorithmParams = getAlgorithmParams(config, iv);
    const cipherBuffer = base64ToArrayBuffer(payload.ciphertext);
    const plainBuffer = await window.crypto.subtle.decrypt(
      algorithmParams,
      key,
      cipherBuffer
    );
    return { success: true, data: textDecoder.decode(plainBuffer) };
  } catch (error) {
    return { success: false, data: error.message };
  }
}

function showDecryptResult(version, result) {
  const clone = decryptTemplate.content.firstElementChild.cloneNode(true);
  clone.querySelector('h3').textContent = version;
  const status = clone.querySelector('.status');
  const code = clone.querySelector('code');
  if (result.success) {
    status.textContent = '복호화 성공';
    status.classList.remove('muted');
    code.textContent = result.data;
  } else {
    status.textContent = '복호화 실패';
    status.classList.add('muted');
    code.textContent = result.data;
  }
  decryptResults.appendChild(clone);
}

encryptForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  const plainText = formData.get('plain').trim();
  const passphrase = formData.get('passphrase');
  const version = formData.get('version');

  if (!plainText) {
    alert('암호화할 텍스트를 입력해주세요.');
    return;
  }

  event.submitter.disabled = true;
  event.submitter.textContent = '암호화 중...';

  try {
    const payload = await encryptText({ version, plainText, passphrase });
    encryptOutput.textContent = JSON.stringify(payload, null, 2);
    encryptResult.hidden = false;
  } catch (error) {
    alert(`암호화에 실패했습니다: ${error.message}`);
  } finally {
    event.submitter.disabled = false;
    event.submitter.textContent = '텍스트 암호화';
  }
});

decryptForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  const payloadRaw = formData.get('payload');
  const passphrase = formData.get('passphrase');

  let payload;
  try {
    payload = JSON.parse(payloadRaw);
  } catch (error) {
    alert('유효한 JSON 형식의 암호화 데이터를 입력해주세요.');
    return;
  }

  decryptResults.innerHTML = '';
  event.submitter.disabled = true;
  event.submitter.textContent = '복호화 중...';

  for (const version of Object.keys(METHOD_CONFIGS)) {
    const result = await decryptWithVersion({ version, payload, passphrase });
    showDecryptResult(version, result);
  }

  event.submitter.disabled = false;
  event.submitter.textContent = '모든 방식으로 복호화';
});

copyButton?.addEventListener('click', async () => {
  const text = encryptOutput.textContent;
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    copyButton.textContent = '복사 완료!';
    setTimeout(() => {
      copyButton.textContent = '복사';
    }, 1500);
  } catch (error) {
    alert('클립보드 복사에 실패했습니다.');
  }
});
