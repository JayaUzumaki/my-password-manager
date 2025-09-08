import React from "react";
// To resolve bundling issues in some environments, we'll import from the Supabase CDN.
// In your local Vite project, `import { createClient } from '@supabase/supabase-js'` will also work after `npm install`.
import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm";

// --- Supabase Client Setup ---
// IMPORTANT: Make sure you have a .env.local file in your project root
// with your Supabase credentials, like this:
// VITE_SUPABASE_URL=https://your-project-url.supabase.co
// VITE_SUPABASE_ANON_KEY=your-public-anon-key
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error(
    "Supabase URL or Key is missing. Make sure to set them in your .env.local file."
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
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
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
    <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center font-sans p-4">
      <div className="w-full max-w-2xl mx-auto bg-gray-800 rounded-2xl shadow-lg p-8">
        {!session ? (
          <Auth />
        ) : (
          <Dashboard key={session.user.id} session={session} />
        )}
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
    if (!email) {
      setMessage("Please enter your email.");
      return;
    }
    setLoading(true);
    setMessage("");
    try {
      const { error } = await supabase.auth.signInWithOtp({ email: email });
      if (error) throw error;
      setMessage("Check your email for the login link!");
    } catch (error) {
      console.error("Error logging in:", error.message);
      setMessage(`Error: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="text-center">
        <h1 className="text-3xl font-bold text-gray-100">Password Manager</h1>
        <p className="text-gray-400 mt-2">
          Sign in via magic link with your email below
        </p>
      </div>
      <form onSubmit={handleLogin} className="flex flex-col gap-4">
        <input
          className="bg-gray-700 text-white px-4 py-3 rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-500 transition"
          type="email"
          placeholder="Your email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <button
          className="bg-purple-600 hover:bg-purple-700 text-white font-bold py-3 px-4 rounded-lg transition disabled:opacity-50 disabled:cursor-not-allowed"
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
  const [revealedPassword, setRevealedPassword] = React.useState({});
  const [confirmingDeleteId, setConfirmingDeleteId] = React.useState(null);

  const getPasswords = React.useCallback(async () => {
    setLoadingPasswords(true);
    const { data, error } = await supabase
      .from("passwords")
      .select("id, website_url, username, encrypted_password");
    if (error) {
      console.error("Error fetching passwords:", error);
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
    // Generate 32 random bytes and convert to a Base64 string for the key
    const randomBytes = window.crypto.getRandomValues(new Uint8Array(32));
    const keyfileContent = btoa(String.fromCharCode.apply(null, randomBytes));

    // Create a blob from the key
    const blob = new Blob([keyfileContent], { type: "text/plain" });
    const url = URL.createObjectURL(blob);

    // Create a temporary link to trigger the download
    const a = document.createElement("a");
    a.href = url;
    a.download = "vault-key.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    // Immediately unlock the vault with the new key
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
    const { error } = await supabase.from("passwords").insert({
      website_url: website,
      username: username,
      encrypted_password: encrypted,
      user_id: session.user.id,
    });
    if (error) {
      setError("Failed to add password.");
    } else {
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
      setError("Decryption failed. The key file is likely incorrect.");
    }
  };

  const handleSignOut = async () => {
    await supabase.auth.signOut();
  };

  // --- Locked State Render Logic ---
  if (!decryptionKey) {
    if (loadingPasswords) {
      return (
        <div className="text-center">
          <p>Checking vault...</p>
        </div>
      );
    }

    // First time setup if vault is empty
    if (passwords.length === 0) {
      return (
        <div className="flex flex-col gap-4 text-center items-center">
          <h2 className="text-2xl font-bold">
            Welcome! Let's Secure Your Vault
          </h2>
          <p className="text-gray-400">
            This is your first time, so you need to generate a secure key file.
          </p>
          <div className="bg-yellow-900 border-l-4 border-yellow-400 text-yellow-200 p-4 my-4 text-left">
            <p className="font-bold">VERY IMPORTANT:</p>
            <ul className="list-disc list-inside mt-2 text-sm">
              <li>This file is your ONLY way to access your passwords.</li>
              <li>Save it to a secure, offline location like a USB drive.</li>
              <li>If you lose this file, your data is lost forever.</li>
            </ul>
          </div>
          <button
            onClick={handleGenerateKeyfile}
            className="bg-green-600 hover:bg-green-700 text-white font-bold py-3 px-6 rounded-lg transition"
          >
            Generate and Download Key File
          </button>
        </div>
      );
    }

    // Standard unlock screen for existing vaults
    return (
      <div className="flex flex-col gap-6 text-center">
        <h2 className="text-2xl font-bold">Vault Locked</h2>
        <p className="text-gray-400 mb-4">
          Upload your key file to unlock the vault.
        </p>
        <div>
          <label
            htmlFor="key-file-upload"
            className="bg-purple-600 hover:bg-purple-700 cursor-pointer text-white font-bold py-3 px-8 rounded-lg transition inline-block"
          >
            Upload Key File
          </label>
          <input
            id="key-file-upload"
            type="file"
            className="hidden"
            accept=".txt"
            onChange={handleFileUnlock}
          />
          <p className="text-xs text-gray-500 mt-2">
            Select the `vault-key.txt` file you saved.
          </p>
        </div>
        {error && <p className="text-red-400 mt-2">{error}</p>}
      </div>
    );
  }

  // --- Unlocked State Render Logic (Main Dashboard) ---
  return (
    <div className="flex flex-col gap-8">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold text-gray-100">My Vault</h1>
        <button
          onClick={handleSignOut}
          className="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-lg transition"
        >
          {" "}
          Sign Out{" "}
        </button>
      </div>

      <div className="bg-gray-900 p-6 rounded-lg">
        <h2 className="text-xl font-semibold mb-4">Add New Password</h2>
        <form
          onSubmit={handleAddPassword}
          className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end"
        >
          <input
            value={website}
            onChange={(e) => setWebsite(e.target.value)}
            placeholder="Website URL"
            className="bg-gray-700 text-white px-3 py-2 rounded-lg border border-gray-600 md:col-span-2"
          />
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Username/Email"
            className="bg-gray-700 text-white px-3 py-2 rounded-lg border border-gray-600"
          />
          <input
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            type="password"
            placeholder="Password"
            className="bg-gray-700 text-white px-3 py-2 rounded-lg border border-gray-600"
          />
          <button
            type="submit"
            className="bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded-lg md:col-span-4"
          >
            Add Password
          </button>
        </form>
        {error && <p className="text-red-400 mt-4">{error}</p>}
      </div>

      <div className="flex flex-col gap-3">
        {loadingPasswords && <p>Loading passwords...</p>}
        {passwords.length === 0 && !loadingPasswords && (
          <p className="text-center text-gray-400">Your vault is empty.</p>
        )}
        {passwords.map((p) => (
          <div
            key={p.id}
            className="bg-gray-700 p-4 rounded-lg flex items-center justify-between gap-4 flex-wrap"
          >
            <div className="flex-grow">
              <p className="font-bold text-lg text-purple-300">
                {p.website_url}
              </p>
              <p className="text-gray-300">{p.username}</p>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <div className="w-40 text-center">
                {revealedPassword[p.id] ? (
                  <span className="font-mono bg-gray-800 p-1 rounded break-all">
                    {revealedPassword[p.id]}
                  </span>
                ) : (
                  <span className="font-mono">••••••••</span>
                )}
              </div>
              <button
                onClick={() => revealPassword(p.id, p.encrypted_password)}
                className="bg-blue-500 hover:bg-blue-600 text-white py-1 px-3 rounded"
              >
                {revealedPassword[p.id] ? "Hide" : "Reveal"}
              </button>
              {confirmingDeleteId === p.id ? (
                <button
                  onClick={() => handleDeletePassword(p.id)}
                  className="bg-yellow-500 hover:bg-yellow-600 text-white py-1 px-3 rounded"
                >
                  Confirm?
                </button>
              ) : (
                <button
                  onClick={() => setConfirmingDeleteId(p.id)}
                  className="bg-red-500 hover:bg-red-600 text-white py-1 px-3 rounded"
                >
                  Delete
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
