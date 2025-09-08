import React from "react";
// In your local Vite project, `import { createClient } from '@supabase/supabase-js'` is the standard way.
// This CDN import is used to ensure compatibility in different preview environments.
import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm";

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error(
    "Supabase URL or Key is missing. Make sure to set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in your .env.local file."
  );
}
const supabase = createClient(supabaseUrl, supabaseKey);

// --- Crypto Helper Functions ---
async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode(salt),
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function encrypt(text, key) {
  const enc = new TextEncoder();
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encryptedContent = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    enc.encode(text)
  );
  const result = new Uint8Array(
    iv.length + new Uint8Array(encryptedContent).length
  );
  result.set(iv, 0);
  result.set(new Uint8Array(encryptedContent), iv.length);
  return btoa(String.fromCharCode.apply(null, result));
}

async function decrypt(encryptedText, key) {
  try {
    const binaryString = atob(encryptedText);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    const iv = bytes.slice(0, 12);
    const encryptedContent = bytes.slice(12);
    const decryptedContent = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      encryptedContent
    );
    return new TextDecoder().decode(decryptedContent);
  } catch (e) {
    console.error("Decryption failed:", e);
    return null;
  }
}

function generateSecurePassword() {
  const length = 18;
  const lower = "abcdefghijklmnopqrstuvwxyz",
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    numbers = "0123456789",
    symbols = "!@#$%^&*()_+~`|}{[]:;?><,./-=";
  let password = [
    lower[Math.floor(Math.random() * lower.length)],
    upper[Math.floor(Math.random() * upper.length)],
    numbers[Math.floor(Math.random() * numbers.length)],
    symbols[Math.floor(Math.random() * symbols.length)],
  ];
  const allChars = lower + upper + numbers + symbols;
  for (let i = password.length; i < length; i++) {
    password.push(allChars[Math.floor(Math.random() * allChars.length)]);
  }
  return password.sort(() => Math.random() - 0.5).join("");
}

// --- Main App Component ---
export default function App() {
  const [session, setSession] = React.useState(null);

  React.useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
    });
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
    });
    return () => subscription.unsubscribe();
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-slate-800 text-slate-100 flex items-center justify-center font-sans p-4 selection:bg-violet-500 selection:text-white">
      <div className="w-full max-w-3xl mx-auto backdrop-blur-sm bg-black/30 rounded-2xl shadow-2xl shadow-black/40 border border-white/10">
        <div className="p-6 sm:p-8">
          {!session ? (
            <Auth />
          ) : (
            <Dashboard key={session.user.id} session={session} />
          )}
        </div>
      </div>
    </div>
  );
}

// --- Authentication Component ---
function Auth() {
  const [loading, setLoading] = React.useState(false);
  const [email, setEmail] = React.useState("");
  const [message, setMessage] = React.useState("");

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage("");
    try {
      const { error } = await supabase.auth.signInWithOtp({ email });
      if (error) throw error;
      setMessage("Check your email for the magic link!");
    } catch (error) {
      setMessage(`Error: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col gap-6 animate-fade-in">
      <div className="text-center">
        <h1 className="text-3xl sm:text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-violet-400 to-purple-500">
          Secure Vault
        </h1>
        <p className="text-slate-400 mt-2">
          Passwordless sign-in for ultimate security.
        </p>
      </div>
      <form onSubmit={handleLogin} className="flex flex-col gap-4">
        <input
          className="bg-slate-800/60 px-4 py-3 rounded-lg border border-white/10 focus:outline-none focus:ring-2 focus:ring-violet-500 transition-all duration-300"
          type="email"
          placeholder="Enter your email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <button
          className="bg-violet-600 hover:bg-violet-700 font-bold py-3 px-4 rounded-lg transition-all duration-300 disabled:opacity-50 transform hover:scale-105 active:scale-100"
          disabled={loading}
        >
          {loading ? "Sending..." : "Send Magic Link"}
        </button>
      </form>
      {message && <p className="text-center text-green-400 mt-2">{message}</p>}
    </div>
  );
}

// --- Dashboard Component ---
function Dashboard({ session }) {
  const [decryptionKey, setDecryptionKey] = React.useState(null);
  const [error, setError] = React.useState(null);
  const [passwords, setPasswords] = React.useState([]);
  const [loadingPasswords, setLoadingPasswords] = React.useState(true);

  const [website, setWebsite] = React.useState("");
  const [username, setUsername] = React.useState("");
  const [newPassword, setNewPassword] = React.useState("");
  const [searchQuery, setSearchQuery] = React.useState("");

  const [revealedPassword, setRevealedPassword] = React.useState({});
  const [confirmingDeleteId, setConfirmingDeleteId] = React.useState(null);
  const [copiedInfo, setCopiedInfo] = React.useState({ id: null, timer: null });

  const getPasswords = React.useCallback(async () => {
    setLoadingPasswords(true);
    const { data, error } = await supabase
      .from("passwords")
      .select("id, website_url, username, encrypted_password");
    if (error) {
      setError("Could not fetch passwords.");
    } else {
      setPasswords(data);
    }
    setLoadingPasswords(false);
  }, []);

  React.useEffect(() => {
    getPasswords();
    const channel = supabase
      .channel("passwords")
      .on(
        "postgres_changes",
        { event: "*", schema: "public", table: "passwords" },
        () => getPasswords()
      )
      .subscribe();
    return () => {
      supabase.removeChannel(channel);
    };
  }, [getPasswords]);

  const filteredPasswords = React.useMemo(() => {
    return passwords.filter(
      (p) =>
        p.website_url.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.username.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }, [passwords, searchQuery]);

  const setKeyAndUnlock = async (keyfileContent) => {
    if (!keyfileContent) {
      setError("Key file content cannot be empty.");
      return;
    }
    setError(null);
    const key = await deriveKey(keyfileContent, session.user.email);
    setDecryptionKey(key);
  };

  const handleGenerateKeyfile = async () => {
    const randomBytes = window.crypto.getRandomValues(new Uint8Array(32));
    const keyfileContent = btoa(String.fromCharCode.apply(null, randomBytes));
    const blob = new Blob([keyfileContent], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vault-key.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    await setKeyAndUnlock(keyfileContent);
  };

  const handleFileUnlock = async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (e) => {
      await setKeyAndUnlock(e.target.result.trim());
    };
    reader.readAsText(file);
    event.target.value = null;
  };

  const handleAddPassword = async (e) => {
    e.preventDefault();
    if (!website || !username || !newPassword) {
      setError("Please fill all fields.");
      return;
    }
    setError(null);
    const encrypted = await encrypt(newPassword, decryptionKey);
    const { data: newPasswordData, error } = await supabase
      .from("passwords")
      .insert({
        website_url: website,
        username: username,
        encrypted_password: encrypted,
        user_id: session.user.id,
      })
      .select()
      .single();
    if (error) {
      setError("Failed to add password.");
    } else if (newPasswordData) {
      setPasswords((prev) => [...prev, newPasswordData]);
      setWebsite("");
      setUsername("");
      setNewPassword("");
    }
  };

  const handleDeletePassword = async (id) => {
    const { error } = await supabase.from("passwords").delete().match({ id });
    if (error) {
      setError("Failed to delete password.");
    } else {
      setPasswords((prev) => prev.filter((p) => p.id !== id));
      setConfirmingDeleteId(null);
    }
  };

  const revealPassword = async (id, encryptedPass) => {
    if (revealedPassword[id]) {
      setRevealedPassword((prev) => ({ ...prev, [id]: null }));
      return;
    }
    const decrypted = await decrypt(encryptedPass, decryptionKey);
    if (decrypted) {
      setRevealedPassword((prev) => ({ ...prev, [id]: decrypted }));
    } else {
      setError("Decryption failed. Key file may be incorrect.");
    }
  };

  const handleGeneratePassword = () => {
    setNewPassword(generateSecurePassword());
  };

  const handleCopyToClipboard = (text, id) => {
    navigator.clipboard
      .writeText(text)
      .then(() => {
        if (copiedInfo.timer) clearTimeout(copiedInfo.timer);
        const timer = setTimeout(
          () => setCopiedInfo({ id: null, timer: null }),
          2000
        );
        setCopiedInfo({ id, timer });
      })
      .catch((err) => console.error("Could not copy text: ", err));
  };

  if (!decryptionKey) {
    if (loadingPasswords)
      return (
        <div className="text-center p-8">
          <p>Checking vault status...</p>
        </div>
      );
    if (passwords.length === 0) {
      return (
        <div className="flex flex-col gap-4 text-center items-center animate-fade-in p-4">
          <h2 className="text-2xl sm:text-3xl font-bold">
            Secure Your New Vault
          </h2>
          <p className="text-slate-400 max-w-md">
            To begin, you need to generate a unique key file. This is the only
            way to access your encrypted data.
          </p>
          <div className="bg-yellow-900/50 border border-yellow-400/30 text-yellow-200 p-4 my-4 text-left rounded-lg">
            <p className="font-bold">CRITICAL INFORMATION:</p>
            <ul className="list-disc list-inside mt-2 text-sm space-y-1">
              <li>
                Store this file in a secure, offline location (e.g., a USB
                drive).
              </li>
              <li>Do NOT store it on your desktop or in cloud storage.</li>
              <li>If you lose this file, your data is PERMANENTLY lost.</li>
            </ul>
          </div>
          <button
            onClick={handleGenerateKeyfile}
            className="bg-green-600 hover:bg-green-700 text-white font-bold py-3 px-6 rounded-lg transition-all duration-300 transform hover:scale-105 active:scale-100"
          >
            {" "}
            Generate & Download Key File{" "}
          </button>
        </div>
      );
    }
    return (
      <div className="flex flex-col gap-6 text-center animate-fade-in p-4">
        <h2 className="text-2xl sm:text-3xl font-bold">Vault Locked</h2>
        <p className="text-slate-400 mb-4">
          Please upload your key file to decrypt and access your data.
        </p>
        <div>
          <label
            htmlFor="key-file-upload"
            className="bg-violet-600 hover:bg-violet-700 cursor-pointer text-white font-bold py-3 px-8 rounded-lg transition-all duration-300 inline-flex items-center gap-2 transform hover:scale-105 active:scale-100"
          >
            <i className="fa-solid fa-upload w-5 h-5"></i>
            <span>Upload Key File</span>
          </label>
          <input
            id="key-file-upload"
            type="file"
            className="hidden"
            accept=".txt"
            onChange={handleFileUnlock}
          />
        </div>
        {error && <p className="text-red-400 mt-2">{error}</p>}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-8 animate-fade-in">
      <header className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2">
        <h1 className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-violet-400 to-purple-500">
          My Vault
        </h1>
        <button
          onClick={() => supabase.auth.signOut()}
          className="bg-red-600/80 hover:bg-red-600 text-white font-bold py-2 px-4 rounded-lg transition-all text-sm self-start sm:self-center"
        >
          {" "}
          Sign Out{" "}
        </button>
      </header>

      <section className="bg-black/20 p-4 sm:p-6 rounded-lg border border-white/10">
        <h2 className="text-xl font-semibold mb-4">Add New Credential</h2>
        <form
          onSubmit={handleAddPassword}
          className="grid grid-cols-1 md:grid-cols-2 gap-4"
        >
          <input
            value={website}
            onChange={(e) => setWebsite(e.target.value)}
            placeholder="Website URL (e.g., google.com)"
            className="bg-slate-800/60 px-3 py-2 rounded-lg border border-white/10 focus:outline-none focus:ring-2 focus:ring-violet-500 transition-all"
          />
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Username or Email"
            className="bg-slate-800/60 px-3 py-2 rounded-lg border border-white/10 focus:outline-none focus:ring-2 focus:ring-violet-500 transition-all"
          />
          <div className="relative md:col-span-2">
            <input
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              type="text"
              placeholder="Password"
              className="bg-slate-800/60 w-full pr-10 px-3 py-2 rounded-lg border border-white/10 focus:outline-none focus:ring-2 focus:ring-violet-500 transition-all"
            />
            <button
              type="button"
              onClick={handleGeneratePassword}
              title="Generate Secure Password"
              className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-violet-400 transition-colors"
            >
              <i className="fa-solid fa-wand-magic-sparkles w-5 h-5"></i>
            </button>
          </div>
          <button
            type="submit"
            className="bg-green-600 hover:bg-green-700 font-bold py-2 px-4 rounded-lg transition-all md:col-span-2 transform hover:scale-[1.02] active:scale-100"
          >
            Add Credential
          </button>
        </form>
        {error && <p className="text-red-400 mt-4 text-center">{error}</p>}
      </section>

      <section className="flex flex-col gap-4">
        <div className="relative">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search vault..."
            className="bg-slate-800/60 w-full pl-10 pr-4 py-2 rounded-lg border border-white/10 focus:outline-none focus:ring-2 focus:ring-violet-500 transition-all"
          />
          <i className="fa-solid fa-search absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"></i>
        </div>

        {loadingPasswords && (
          <p className="text-center text-slate-400">Loading credentials...</p>
        )}
        {!filteredPasswords.length && !loadingPasswords && (
          <p className="text-center text-slate-400 p-4">
            {passwords.length > 0
              ? "No results found."
              : "Your vault is empty."}
          </p>
        )}

        {filteredPasswords.map((p) => (
          <div
            key={p.id}
            className="bg-black/20 p-4 rounded-lg border border-white/10 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
          >
            <div className="flex items-center gap-4 flex-grow">
              <img
                src={`https://www.google.com/s2/favicons?sz=64&domain_url=${p.website_url}`}
                alt="site icon"
                className="w-8 h-8 rounded-full bg-slate-700 object-contain p-1"
                onError={(e) => {
                  // Fallback to a generic icon if the favicon fails to load
                  e.target.onerror = null;
                  e.target.src = `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='64' height='64' viewBox='0 0 24 24' fill='none' stroke='rgb(148,163,184)' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='12' cy='12' r='10'%3E%3C/circle%3E%3Cpath d='M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20'%3E%3C/path%3E%3Cpath d='M2 12h20'%3E%3C/path%3E%3C/svg%3E`;
                }}
              />
              <div className="flex-grow">
                <p className="font-bold text-lg text-violet-300 break-words">
                  {p.website_url}
                </p>
                <div className="flex items-center gap-2">
                  <p className="text-slate-300 break-words">{p.username}</p>
                  <button
                    onClick={() =>
                      handleCopyToClipboard(p.username, `${p.id}-user`)
                    }
                    title="Copy Username"
                    className="text-slate-400 hover:text-white transition-colors"
                  >
                    {copiedInfo.id === `${p.id}-user` ? (
                      <i className="fa-solid fa-check w-4 h-4 text-green-400"></i>
                    ) : (
                      <i className="fa-solid fa-copy w-4 h-4"></i>
                    )}
                  </button>
                </div>
                {revealedPassword[p.id] && (
                  <div className="flex items-center gap-2 mt-2">
                    <span className="font-mono text-sm bg-slate-800 p-1 rounded break-all">
                      {revealedPassword[p.id]}
                    </span>
                    <button
                      onClick={() =>
                        handleCopyToClipboard(revealedPassword[p.id], p.id)
                      }
                      title="Copy Password"
                      className="text-slate-400 hover:text-white transition-colors"
                    >
                      {copiedInfo.id === p.id ? (
                        <i className="fa-solid fa-check w-4 h-4 text-green-400"></i>
                      ) : (
                        <i className="fa-solid fa-copy w-4 h-4"></i>
                      )}
                    </button>
                  </div>
                )}
              </div>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0 self-end sm:self-center">
              <button
                onClick={() => revealPassword(p.id, p.encrypted_password)}
                title={
                  revealedPassword[p.id] ? "Hide Password" : "Reveal Password"
                }
                className="p-2 bg-slate-700/50 hover:bg-slate-700 rounded-md transition-colors"
              >
                {revealedPassword[p.id] ? (
                  <i className="fa-solid fa-eye-slash w-5 h-5"></i>
                ) : (
                  <i className="fa-solid fa-eye w-5 h-5"></i>
                )}
              </button>
              {confirmingDeleteId === p.id ? (
                <button
                  onClick={() => handleDeletePassword(p.id)}
                  className="p-2 bg-yellow-500/80 hover:bg-yellow-500 rounded-md transition-colors text-white font-bold text-xs"
                >
                  Confirm?
                </button>
              ) : (
                <button
                  onClick={() => setConfirmingDeleteId(p.id)}
                  title="Delete Credential"
                  className="p-2 bg-red-600/80 hover:bg-red-600 rounded-md transition-colors"
                >
                  <i className="fa-solid fa-trash-can w-5 h-5"></i>
                </button>
              )}
            </div>
          </div>
        ))}
      </section>
    </div>
  );
}
